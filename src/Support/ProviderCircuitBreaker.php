<?php

namespace Uzairports\Uzairid\Support;

use Closure;
use Illuminate\Contracts\Cache\Repository as CacheRepository;
use Throwable;

/**
 * Leaves a failing identity provider alone once its failures add up.
 *
 * An unreachable provider would otherwise cost every request with an expiring
 * token a full request timeout held in a worker, exhausting workers during a
 * wave of expiries. After `provider_failure_threshold` failures within one
 * `provider_cooldown`, `isOpen()` answers true for `provider_cooldown` seconds
 * and renewals are answered from the row.
 *
 * A single failure never trips it: blips (dropped connections, rate limits)
 * are normal, and a successful exchange clears the count. There is no
 * half-open probe; the entry lapses, so the cooldown should be several times
 * the request timeout. A per-process store is acceptable here because the
 * breaker only spares work.
 *
 * Nothing here ever raises: a store that will not answer is treated as no
 * cooldown, because a renewal must never be refused over the cache.
 */
final class ProviderCircuitBreaker
{
    /**
     * Cache key marking the provider as in cooldown.
     */
    private const string OPEN_KEY = 'uzairid:provider-unreachable';

    /**
     * Cache key counting provider failures below the threshold.
     */
    private const string FAILURE_COUNT_KEY = 'uzairid:provider-failures';

    /**
     * @param  Closure(): mixed  $store  resolves the `lock_store` store lazily, so a
     *                                   store that cannot be resolved is caught here
     */
    public function __construct(private readonly Closure $store) {}

    /**
     * Whether the provider is in cooldown after repeated failures.
     *
     * @phpstan-impure
     */
    public function isOpen(): bool
    {
        if (self::cooldown() === 0) {
            return false;
        }

        try {
            return $this->cache()?->has(self::OPEN_KEY) === true;
        } catch (Throwable) {
            return false;
        }
    }

    /**
     * Count a failure to answer and start the cooldown at the threshold.
     *
     * Refused grants are not counted; the provider answered. The count lives
     * for one cooldown, and `add()` precedes `increment()` because incrementing
     * a missing key creates it without a TTL on some stores.
     */
    public function recordFailure(): void
    {
        $cooldown = self::cooldown();

        if ($cooldown === 0) {
            return;
        }

        try {
            $cache = $this->cache();

            if ($cache === null) {
                return;
            }

            $threshold = self::failureThreshold();

            if ($threshold > 1) {
                $cache->add(self::FAILURE_COUNT_KEY, 0, $cooldown);

                if ((int) $cache->increment(self::FAILURE_COUNT_KEY) < $threshold) {
                    return;
                }
            }

            $cache->put(self::OPEN_KEY, true, $cooldown);
        } catch (Throwable) {
            // Never fail a renewal over the breaker.
        }
    }

    /**
     * Clear the count after a successful exchange, so isolated failures never
     * accumulate into a cooldown. Skipped while the breaker is disabled.
     */
    public function recordSuccess(): void
    {
        if (self::cooldown() === 0) {
            return;
        }

        $this->reset();
    }

    /**
     * End the cooldown and clear the count, whatever the configuration says.
     */
    public function reset(): void
    {
        try {
            $cache = $this->cache();

            $cache?->forget(self::FAILURE_COUNT_KEY);
            $cache?->forget(self::OPEN_KEY);
        } catch (Throwable) {
            // An unreachable store holds nothing to clear.
        }
    }

    /**
     * Cooldown length in seconds; zero disables the breaker.
     */
    public static function cooldown(): int
    {
        $configured = config('uzairports.provider_cooldown', 30);

        return max(is_numeric($configured) ? (int) $configured : 30, 0);
    }

    /**
     * Failures within one cooldown that start it (minimum 1).
     */
    public static function failureThreshold(): int
    {
        $configured = config('uzairports.provider_failure_threshold', 5);

        return max(is_numeric($configured) ? (int) $configured : 5, 1);
    }

    /**
     * The store holding the entries, or null when `lock_store` is not a cache
     * repository (a bare `LockProvider`), in which case the breaker is off.
     */
    private function cache(): ?CacheRepository
    {
        $repository = ($this->store)();

        return $repository instanceof CacheRepository ? $repository : null;
    }
}
