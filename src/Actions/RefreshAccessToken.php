<?php

namespace Uzairports\Uzairid\Actions;

use GuzzleHttp\Exception\BadResponseException;
use Illuminate\Cache\ArrayStore;
use Illuminate\Cache\Repository;
use Illuminate\Contracts\Cache\Lock;
use Illuminate\Contracts\Cache\LockProvider;
use Illuminate\Contracts\Cache\LockTimeoutException;
use Illuminate\Contracts\Cache\Repository as CacheRepository;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Log;
use Laravel\Socialite\Facades\Socialite;
use Symfony\Component\HttpKernel\Exception\ServiceUnavailableHttpException;
use Throwable;
use Uzairports\Uzairid\Events\UzairTokenRefreshed;
use Uzairports\Uzairid\Events\UzairTokenRefreshFailed;
use Uzairports\Uzairid\Models\OauthToken;
use Uzairports\Uzairid\Socialite\UzairportsProvider;

class RefreshAccessToken
{
    /**
     * Exchange the stored refresh token for a fresh access token.
     *
     * The provider rotates refresh tokens, so each may be spent only once. The
     * exchange runs behind a lock; a request that waited reads the token the
     * winner stored instead of spending it again. `$leeway` is the margin the
     * caller used to decide the token needed renewing.
     *
     * Returns false when the provider refuses the grant; the user must sign in
     * again. The cooldown check (`providerIsUnreachable()`) runs before the lock
     * so that requests do not hold workers waiting on a failing provider. A lock
     * store failure is answered from the row, never by exchanging unguarded,
     * while failures from the exchange itself propagate to the caller untouched.
     *
     * @throws Throwable
     */
    public function __invoke(OauthToken $token, int $leeway = 0): bool
    {
        if ($this->providerIsUnreachable()) {
            return $this->answerWithoutCalling($token, $leeway);
        }

        try {
            $store = $this->lockStore();
        } catch (Throwable $exception) {
            return $this->refuseOverTheLockStore($token, $leeway, $exception);
        }

        if ($store === null) {
            return $this->exchange($token, $leeway);
        }

        // Acquisition and work are kept apart (not a `block()` callback) so a
        // lock store failure is never confused with a failed exchange, whose
        // error the caller must receive.
        try {
            /** @var Lock $lock */
            $lock = $store->lock($this->lockKey($token), self::lockTtl());

            $lock->block(self::lockWait());
        } catch (LockTimeoutException) {
            return $this->answerWithoutCalling($token, $leeway);
        } catch (Throwable $exception) {
            return $this->refuseOverTheLockStore($token, $leeway, $exception);
        }

        try {
            // The holder this request waited for may have tripped the cooldown;
            // calling the provider again would hold this worker for a timeout too.
            if ($this->providerIsUnreachable()) {
                return $this->answerWithoutCalling($token, $leeway);
            }

            return $this->exchange($token, $leeway);
        } finally {
            $this->release($lock);
        }
    }

    /**
     * Release the lock, reporting rather than raising a store failure.
     *
     * This runs in a `finally`, where an exception would replace the result of
     * the exchange (a successful renewal or the real failure). The lock expires
     * on its own after `lockTtl()`, so swallowing the error is safe.
     */
    private function release(Lock $lock): void
    {
        try {
            $lock->release();
        } catch (Throwable $exception) {
            self::warnAboutTheLockStore(
                'The cache store behind [uzairports.lock_store] would not release the lock that guards the UzAirports refresh token exchange, which will now be held until it expires. ('.$exception::class.')'
            );
        }
    }

    /**
     * Answer from the row when the lock store fails (unreachable, misnamed).
     *
     * Same answer as a lock timeout, via `answerWithoutCalling()`. Never fall
     * back to an unguarded exchange: while the store is down nobody holds the
     * lock, so every concurrent renewal would spend the same rotating token.
     * This differs from `lockStore()` returning null, which is a standing
     * misconfiguration logged once, not a transient outage.
     *
     * @throws ServiceUnavailableHttpException when the login is still due a renewal
     */
    private function refuseOverTheLockStore(OauthToken $token, int $leeway, Throwable $exception): bool
    {
        self::warnAboutTheLockStore(
            'The cache store behind [uzairports.lock_store] would not hold the lock that guards the UzAirports refresh token exchange, so renewals are being answered from what is stored rather than spent unguarded. ('.$exception::class.')'
        );

        return $this->answerWithoutCalling($token, $leeway);
    }

    /**
     * Answer from the row alone, without spending the refresh token.
     *
     * Adopts a login another process renewed, returns false for one that is
     * gone, lets through one whose access token has not expired yet, and
     * otherwise throws 503. Never return false for a still-due login:
     * the middleware would end it, so a brief outage would sign out every user,
     * who could not sign back in through the same provider.
     *
     * @throws ServiceUnavailableHttpException when the login is still due a renewal
     */
    private function answerWithoutCalling(OauthToken $token, int $leeway): bool
    {
        $adopted = $this->reload($token, $leeway);

        if ($adopted !== null) {
            return $adopted;
        }

        // Due for renewal is not expired: inside the leeway the access token
        // still works, so the request goes through on it.
        if (! $token->hasExpired()) {
            return true;
        }

        throw $this->temporarilyUnavailable();
    }

    /**
     * Cache key marking the provider as in cooldown.
     */
    private const string PROVIDER_FAILURE_KEY = 'uzairid:provider-unreachable';

    /**
     * Cache key counting consecutive provider failures below the threshold.
     */
    private const string PROVIDER_FAILURE_COUNT_KEY = 'uzairid:provider-failures';

    /**
     * Whether the provider is in cooldown after repeated failures.
     *
     * An unreachable provider would otherwise cost every request with an
     * expiring token a full request timeout held in a worker, exhausting
     * workers during a wave of expiries. After `provider_failure_threshold`
     * failures, the exchange is skipped for `provider_cooldown` seconds and
     * requests are answered from the row.
     *
     * A single failure never trips the breaker: blips (dropped connections,
     * rate limits) are normal, and a successful exchange clears the count.
     * There is no half-open probe; the entry lapses, so the cooldown should be
     * several times the request timeout. A per-process store is acceptable
     * here because the breaker only spares work.
     *
     * @phpstan-impure
     */
    private function providerIsUnreachable(): bool
    {
        if (self::providerCooldown() === 0) {
            return false;
        }

        try {
            return $this->breakerCache()?->has(self::PROVIDER_FAILURE_KEY) === true;
        } catch (Throwable) {
            // Never refuse a renewal over the cache; treat it as no cooldown.
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
    private function recordProviderFailure(): void
    {
        $cooldown = self::providerCooldown();

        if ($cooldown === 0) {
            return;
        }

        try {
            $cache = $this->breakerCache();

            if ($cache === null) {
                return;
            }

            $threshold = self::providerFailureThreshold();

            if ($threshold > 1) {
                $cache->add(self::PROVIDER_FAILURE_COUNT_KEY, 0, $cooldown);

                if ((int) $cache->increment(self::PROVIDER_FAILURE_COUNT_KEY) < $threshold) {
                    return;
                }
            }

            $cache->put(self::PROVIDER_FAILURE_KEY, true, $cooldown);
        } catch (Throwable) {
            // Never fail a renewal over the breaker.
        }
    }

    /**
     * Clear the failure count after a successful exchange, so isolated
     * failures never accumulate into a cooldown.
     */
    private function forgetProviderFailures(): void
    {
        if (self::providerCooldown() === 0) {
            return;
        }

        try {
            $cache = $this->breakerCache();

            $cache?->forget(self::PROVIDER_FAILURE_COUNT_KEY);
            $cache?->forget(self::PROVIDER_FAILURE_KEY);
        } catch (Throwable) {
            // An unreachable store holds nothing to clear.
        }
    }

    /**
     * Failures within one cooldown that start it (minimum 1).
     */
    private static function providerFailureThreshold(): int
    {
        $configured = config('uzairports.provider_failure_threshold', 5);

        return max(is_numeric($configured) ? (int) $configured : 5, 1);
    }

    /**
     * End the cooldown immediately (for operators and tests).
     */
    public static function forgetProviderFailure(): void
    {
        try {
            $cache = (new self)->breakerCache();

            $cache?->forget(self::PROVIDER_FAILURE_COUNT_KEY);
            $cache?->forget(self::PROVIDER_FAILURE_KEY);
        } catch (Throwable) {
            // An unreachable store holds nothing to clear.
        }
    }

    /**
     * Cooldown length in seconds; zero disables the breaker.
     */
    private static function providerCooldown(): int
    {
        $configured = config('uzairports.provider_cooldown', 30);

        return max(is_numeric($configured) ? (int) $configured : 30, 0);
    }

    /**
     * The `lock_store` store, resolved once and shared by the lock and the
     * breaker.
     *
     * Typed `mixed` because a host may bind anything; `lockStore()` and
     * `breakerCache()` check what they receive.
     */
    private mixed $configuredStore = null;

    private bool $storeWasResolved = false;

    private function configuredStore(): mixed
    {
        if (! $this->storeWasResolved) {
            $configured = config('uzairports.lock_store');

            $this->configuredStore = is_string($configured) && $configured !== ''
                ? Cache::store($configured)
                : Cache::store();

            $this->storeWasResolved = true;
        }

        return $this->configuredStore;
    }

    /**
     * The store holding the breaker entries, or null when `lock_store` is not
     * a cache repository, in which case the breaker is disabled.
     */
    private function breakerCache(): ?CacheRepository
    {
        $repository = $this->configuredStore();

        return $repository instanceof CacheRepository ? $repository : null;
    }

    /**
     * The store the exchange is guarded in, or null if it cannot be guarded.
     *
     * A store without atomic locks returns null (the exchange runs unguarded),
     * and an `ArrayStore` is used but guards nothing across processes. Both are
     * logged once per process; neither fails the renewal, since that would sign
     * the user out over a cache setting. A `file` store shared across servers
     * cannot be detected and is left to the `lock_store` config note.
     */
    private function lockStore(): ?LockProvider
    {
        $repository = $this->configuredStore();

        // Locks come from the underlying store, not the repository.
        $store = $repository instanceof Repository ? $repository->getStore() : $repository;

        if (! $store instanceof LockProvider) {
            self::warnAboutTheLockStore(
                'The cache store behind [uzairports.lock_store] offers no atomic locks, so the UzAirports refresh token exchange runs unguarded and a rotating token may be spent twice.'
            );

            return null;
        }

        if ($store instanceof ArrayStore) {
            self::warnAboutTheLockStore(
                'The cache store behind [uzairports.lock_store] lives in the memory of one process, so it guards nothing between the processes serving this application and an UzAirports refresh token may be spent twice. Point it at a store every process shares.'
            );
        }

        return $store;
    }

    /**
     * Lock store warnings already logged in this process.
     *
     * @var array<string, true>
     */
    private static array $reportedAboutTheLockStore = [];

    /**
     * Allow lock store warnings to be logged again; called from
     * `Uzair::flushState()` and by tests.
     */
    public static function flushLockStoreWarnings(): void
    {
        self::$reportedAboutTheLockStore = [];
    }

    /**
     * Log a lock store warning once per process, since this is on the hot path.
     */
    private static function warnAboutTheLockStore(string $message): void
    {
        if (isset(self::$reportedAboutTheLockStore[$message])) {
            return;
        }

        self::$reportedAboutTheLockStore[$message] = true;

        Log::warning($message);
    }

    /**
     * Lock TTL in seconds.
     *
     * Must outlive `lockWait()`: the locked section includes the HTTP exchange
     * plus database reads and writes, and a lock expiring under its holder
     * would let a second request spend the same refresh token.
     */
    private static function lockTtl(): int
    {
        return UzairportsProvider::requestTimeout() + 30;
    }

    /**
     * Seconds to wait for a running exchange; covers the provider's full
     * timeout so the usual outcome is waiting rather than a 503.
     */
    private static function lockWait(): int
    {
        return UzairportsProvider::requestTimeout() + 5;
    }

    /**
     * Spend the refresh token, unless another process already renewed it.
     *
     * A refresh token that cannot be decrypted is treated as missing and
     * returns false, sending the user back through SSO instead of a 500.
     *
     * @throws Throwable
     */
    private function exchange(OauthToken $token, int $leeway): bool
    {
        $adopted = $this->reload($token, $leeway);

        if ($adopted !== null) {
            return $adopted;
        }

        $refreshToken = $token->readableRefreshToken();

        if ($refreshToken === null) {
            UzairTokenRefreshFailed::dispatch($token);

            return false;
        }

        $provider = $this->provider($token);

        try {
            $refreshed = $provider->refreshToken($refreshToken);

            $this->forgetProviderFailures();
        } catch (Throwable $e) {
            $oauthError = $this->oauthError($e);

            Log::warning('Failed to refresh UzAirports access token.', [
                'user_id' => $token->user_id,
                'exception_class' => $e::class,
                'http_status' => $e instanceof BadResponseException ? $e->getResponse()->getStatusCode() : null,
                'oauth_error' => $oauthError,
            ]);

            UzairTokenRefreshFailed::dispatch($token, $e);

            if (in_array($oauthError, self::CLIENT_ERRORS, true)) {
                $this->refuseTheClient($token, $oauthError);
            }

            if ($this->grantWasRejected($e)) {
                return false;
            }

            $this->recordProviderFailure();

            throw $this->temporarilyUnavailable();
        }

        if (blank($refreshed->token)) {
            Log::warning('UzAirports refresh token exchange returned empty access token', [
                'user_id' => $token->user_id,
            ]);

            UzairTokenRefreshFailed::dispatch($token);

            throw $this->temporarilyUnavailable();
        }

        $expiresIn = $refreshed->expiresIn;
        if ($expiresIn <= 0) {
            $fallbackTtl = config('uzairports.default_token_ttl', 3600);
            $expiresIn = is_numeric($fallbackTtl) && (int) $fallbackTtl > 0 ? (int) $fallbackTtl : 0;
        }

        $token->forceFill([
            'access_token' => $refreshed->token,
            'refresh_token' => $refreshed->refreshToken ?: $refreshToken,
            'expires_at' => $expiresIn <= 0
                ? null
                : now()->addSeconds($expiresIn),
        ]);

        // The exchange stays outside the transaction. Logout takes this same
        // row lock before reading the grants it will delete and surrender.
        try {
            $saved = $token->getConnection()->transaction(function () use ($token): bool {
                $stored = $token->newQuery()->whereKey($token->getKey())->lockForUpdate()->first();

                if ($stored === null) {
                    return false;
                }

                return $token->save();
            });
        } catch (Throwable $exception) {
            app(EndSessions::class)->surrender($token);
            UzairTokenRefreshFailed::dispatch($token, $exception);

            throw $exception;
        }

        if (! $saved) {
            app(EndSessions::class)->surrender($token);
            UzairTokenRefreshFailed::dispatch($token);

            return false;
        }

        UzairTokenRefreshed::dispatch($token);

        return true;
    }

    /**
     * The registered `uzairports` Socialite driver, checked by type.
     *
     * A host may register another driver under that name; it is refused by
     * name here, mirroring `EndSessions::revokeAll()`. The answer is 503, not
     * false (see `answerWithoutCalling()`), and no provider failure is recorded
     * because the provider was never called.
     *
     * @throws ServiceUnavailableHttpException when no usable driver is registered
     */
    private function provider(OauthToken $token): UzairportsProvider
    {
        try {
            $provider = Socialite::driver('uzairports');
        } catch (Throwable $exception) {
            $this->refuseTheDriver($token, $exception::class);
        }

        if (! $provider instanceof UzairportsProvider) {
            $this->refuseTheDriver($token, get_debug_type($provider));
        }

        return $provider;
    }

    /**
     * Log the unexpected driver and answer 503.
     */
    private function refuseTheDriver(OauthToken $token, string $found): never
    {
        Log::warning('The [uzairports] Socialite driver cannot renew an UzAirports login.', [
            'user_id' => $token->user_id,
            'expected' => UzairportsProvider::class,
            'found' => $found,
        ]);

        UzairTokenRefreshFailed::dispatch($token);

        throw $this->temporarilyUnavailable();
    }

    /**
     * Reload the row once and adopt it.
     *
     * - `false`: the row is gone (the login was ended);
     * - `true`: the stored token no longer needs renewing and has been adopted;
     * - `null`: the login exists and is still due.
     */
    private function reload(OauthToken $token, int $leeway): ?bool
    {
        $stored = $token->fresh();

        if ($stored === null) {
            return false;
        }

        $token->setRawAttributes($stored->getAttributes(), sync: true);

        return $token->expiresWithin($leeway) ? null : true;
    }

    private function lockKey(OauthToken $token): string
    {
        return "uzairid:refresh-access-token:{$token->id}";
    }

    /**
     * The RFC 6749 `error` code from a refused exchange, if any.
     *
     * A 400 can mean a dead grant or a misconfigured client; the code tells
     * them apart. `error_description` is deliberately not read, as it may echo
     * request data including credentials.
     */
    private function oauthError(Throwable $exception): ?string
    {
        if (! $exception instanceof BadResponseException) {
            return null;
        }

        $response = $exception->getResponse();

        $body = json_decode((string) $response->getBody(), true);

        if (! is_array($body)) {
            return null;
        }

        $error = $body['error'] ?? null;

        return is_string($error) && $error !== '' ? $error : null;
    }

    /**
     * OAuth error codes that refer to the client, not the grant (RFC 6749 §5.2).
     *
     * They affect every login equally, so they must never be treated as a
     * refused grant: returning false would end each login as it came due, and
     * nobody could sign back in with the same broken credentials.
     *
     * @var list<string>
     */
    private const array CLIENT_ERRORS = ['invalid_client', 'unauthorized_client'];

    /**
     * Log an error that the client credentials were refused and answer 503.
     *
     * Not false (see `CLIENT_ERRORS`), and no provider failure is recorded: the
     * provider answered, and a cooldown would only delay the log line.
     *
     * @throws ServiceUnavailableHttpException always
     */
    private function refuseTheClient(OauthToken $token, string $error): never
    {
        Log::error('UzAirports ID refused this application, so no login can be renewed until its credentials are fixed.', [
            'user_id' => $token->user_id,
            'oauth_error' => $error,
            'client_id' => config('uzairports.client_id'),
        ]);

        throw $this->temporarilyUnavailable();
    }

    /**
     * Whether the provider refused this login's grant, which ends the login.
     *
     * Covers grant errors only; `CLIENT_ERRORS` are excluded. A 401 without a
     * readable OAuth error still counts as a refused grant.
     */
    private function grantWasRejected(Throwable $exception): bool
    {
        if (! $exception instanceof BadResponseException) {
            return false;
        }

        $response = $exception->getResponse();

        $statusCode = $response->getStatusCode();

        if ($statusCode !== 400 && $statusCode !== 401) {
            return false;
        }

        $body = json_decode((string) $response->getBody(), true);

        if (! is_array($body)) {
            return $statusCode === 401;
        }

        $error = $body['error'] ?? null;

        if (in_array($error, self::CLIENT_ERRORS, true)) {
            return false;
        }

        return in_array($error, ['invalid_grant', 'invalid_token'], true)
            || ($statusCode === 401 && ($error === null || is_string($error)));
    }

    private function temporarilyUnavailable(): ServiceUnavailableHttpException
    {
        return new ServiceUnavailableHttpException(10, __('uzairid::messages.temporarily_unavailable'));
    }
}
