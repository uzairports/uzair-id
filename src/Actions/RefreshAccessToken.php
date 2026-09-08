<?php

namespace Uzairports\Uzairid\Actions;

use GuzzleHttp\Exception\RequestException;
use Illuminate\Contracts\Cache\Lock;
use Illuminate\Contracts\Cache\LockProvider;
use Illuminate\Contracts\Cache\LockTimeoutException;
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
     * The identity provider rotates the refresh token, so it may only be spent
     * once: two requests exchanging the same one would leave the loser holding a
     * token the provider has already invalidated. The exchange therefore runs
     * behind a lock, and whoever waited for it reads the token the winner stored
     * instead of spending it again — `$leeway` is the same margin the caller used
     * to decide the token needed renewing.
     *
     * Returns false when the SSO server refuses the exchange, in which case the
     * user has to authenticate again.
     */
    public function __invoke(OauthToken $token, int $leeway = 0): bool
    {
        $store = config('uzairports.lock_store');
        /** @var LockProvider $cache */
        $cache = is_string($store) && $store !== '' ? Cache::store($store) : Cache::store();

        $lockSeconds = UzairportsProvider::requestTimeout() + 5;
        /** @var Lock $lock */
        $lock = $cache->lock($this->lockKey($token), $lockSeconds);

        try {
            /** @var bool $refreshed */
            $refreshed = $lock->block($lockSeconds, fn (): bool => $this->exchange($token, $leeway));

            return $refreshed;
        } catch (LockTimeoutException) {
            if ($this->wasRenewedElsewhere($token, $leeway)) {
                return true;
            }

            if ($token->fresh() === null) {
                return false;
            }

            throw $this->temporarilyUnavailable();
        }
    }

    /**
     * Spend the refresh token, unless another process got there first.
     */
    private function exchange(OauthToken $token, int $leeway): bool
    {
        if ($token->fresh() === null) {
            return false;
        }

        if ($this->wasRenewedElsewhere($token, $leeway)) {
            return true;
        }

        if (blank($token->refresh_token)) {
            UzairTokenRefreshFailed::dispatch($token);

            return false;
        }

        try {
            /** @var UzairportsProvider $provider */
            $provider = Socialite::driver('uzairports');

            $refreshed = $provider->refreshToken($token->refresh_token);
        } catch (Throwable $e) {
            Log::warning('Failed to refresh UzAirports access token.', [
                'user_id' => $token->user_id,
                'exception_class' => $e::class,
                'http_status' => $e instanceof RequestException ? $e->getResponse()?->getStatusCode() : null,
            ]);

            UzairTokenRefreshFailed::dispatch($token, $e);

            if ($this->grantWasRejected($e)) {
                return false;
            }

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
            'refresh_token' => $refreshed->refreshToken ?: $token->refresh_token,
            'expires_at' => $expiresIn <= 0
                ? null
                : now()->addSeconds($expiresIn),
        ])->save();

        UzairTokenRefreshed::dispatch($token);

        return true;
    }

    /**
     * Adopt the stored token and report whether it no longer needs renewing.
     *
     * A token whose row is gone was dropped by a process that already saw the
     * exchange refused, so there is nothing left to adopt.
     */
    private function wasRenewedElsewhere(OauthToken $token, int $leeway): bool
    {
        $stored = $token->fresh();

        if ($stored === null) {
            return false;
        }

        $token->setRawAttributes($stored->getAttributes(), sync: true);

        return ! $token->expiresWithin($leeway);
    }

    private function lockKey(OauthToken $token): string
    {
        return "uzairid:refresh-access-token:{$token->id}";
    }

    private function grantWasRejected(Throwable $exception): bool
    {
        if (! $exception instanceof RequestException || $exception->getResponse()?->getStatusCode() !== 400) {
            return false;
        }

        $response = json_decode((string) $exception->getResponse()->getBody(), true);

        return is_array($response) && ($response['error'] ?? null) === 'invalid_grant';
    }

    private function temporarilyUnavailable(): ServiceUnavailableHttpException
    {
        return new ServiceUnavailableHttpException(10, __('uzairid::messages.temporarily_unavailable'));
    }
}
