<?php

namespace Uzairports\Uzairid\Support;

use Carbon\CarbonInterface;

/**
 * When an issued access token stops being accepted.
 *
 * Shared by the sign-in (`RecordLogin`) and the renewal (`RefreshAccessToken`)
 * so the two cannot drift apart.
 */
final class TokenExpiry
{
    /**
     * The expiry for an `expires_in` the provider sent.
     *
     * A provider that sends none — or zero — gets `default_token_ttl`; null
     * only when that is not a positive number either, which means "unknown".
     */
    public static function fromExpiresIn(mixed $expiresIn): ?CarbonInterface
    {
        $seconds = is_numeric($expiresIn) ? (int) $expiresIn : 0;

        if ($seconds <= 0) {
            $seconds = self::defaultTtl();
        }

        return $seconds <= 0 ? null : now()->addSeconds($seconds);
    }

    /**
     * `uzairports.default_token_ttl` in seconds, or zero when it is not a
     * positive number.
     */
    public static function defaultTtl(): int
    {
        $configured = config('uzairports.default_token_ttl', 3600);

        return is_numeric($configured) && (int) $configured > 0 ? (int) $configured : 0;
    }
}
