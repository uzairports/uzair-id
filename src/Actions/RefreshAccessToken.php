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

        /** @var Lock $lock */
        $lock = $cache->lock($this->lockKey($token), self::lockTtl());

        try {
            /** @var bool $refreshed */
            $refreshed = $lock->block(self::lockWait(), fn (): bool => $this->exchange($token, $leeway));

            return $refreshed;
        } catch (LockTimeoutException) {
            $adopted = $this->reload($token, $leeway);

            if ($adopted !== null) {
                return $adopted;
            }

            throw $this->temporarilyUnavailable();
        }
    }

    /**
     * How long the store holds the lock before taking it back.
     *
     * It outlives the wait rather than matching it. Inside the lock sits the
     * exchange — a round-trip carrying the provider's own timeout — with a read
     * and a writing around it, so a slow database is enough to push the whole
     * thing past a lock that expired at the same moment the next request gave
     * up waiting. The lock would then be released under its holder, and both
     * requests would spend the one thing that may only be spent once.
     */
    private static function lockTtl(): int
    {
        return UzairportsProvider::requestTimeout() + 30;
    }

    /**
     * How long a request waits for the exchange already in front of it.
     *
     * Long enough to cover an exchange running to the provider's full timeout,
     * so the ordinary case is waiting rather than a 503.
     */
    private static function lockWait(): int
    {
        return UzairportsProvider::requestTimeout() + 5;
    }

    /**
     * Spend the refresh token, unless another process got there first.
     *
     * A grant that will not open is treated as one the login does not have.
     * Nothing can be exchanged for it. Raising the decryption failure from
     * here would answer the browser with a 500 on every request instead of
     * sending it back through SSO, which is what a login that cannot renew
     * itself is owed.
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

        try {
            /** @var UzairportsProvider $provider */
            $provider = Socialite::driver('uzairports');

            $refreshed = $provider->refreshToken($refreshToken);
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
            'refresh_token' => $refreshed->refreshToken ?: $refreshToken,
            'expires_at' => $expiresIn <= 0
                ? null
                : now()->addSeconds($expiresIn),
        ])->save();

        UzairTokenRefreshed::dispatch($token);

        return true;
    }

    /**
     * Adopt what is stored and say what it leaves the caller to do.
     *
     * Both callers ask the same two questions of the row — whether the login is
     * still there, and whether somebody else has already renewed it — and
     * asking them one at a time to read the same row twice on the hot path. One
     * read answers both:
     *
     * - `false`: the row is gone. Whoever dropped it had already seen the
     *   exchange refused, so there is nothing left to adopt;
     * - `true`: what is stored no longer needs renewing and has been adopted;
     * - `null`: the login is there and still due.
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

    private function grantWasRejected(Throwable $exception): bool
    {
        if (! $exception instanceof RequestException) {
            return false;
        }

        $response = $exception->getResponse();

        if ($response === null) {
            return false;
        }

        $statusCode = $response->getStatusCode();

        if ($statusCode !== 400 && $statusCode !== 401) {
            return false;
        }

        $body = json_decode((string) $response->getBody(), true);

        if (! is_array($body)) {
            return $statusCode === 401;
        }

        $error = $body['error'] ?? null;

        return in_array($error, ['invalid_grant', 'invalid_token', 'unauthorized_client'], true)
            || ($statusCode === 401 && ($error === null || is_string($error)));
    }

    private function temporarilyUnavailable(): ServiceUnavailableHttpException
    {
        return new ServiceUnavailableHttpException(10, __('uzairid::messages.temporarily_unavailable'));
    }
}
