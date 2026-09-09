<?php

namespace Uzairports\Uzairid\Actions;

use GuzzleHttp\Exception\RequestException;
use Illuminate\Cache\ArrayStore;
use Illuminate\Cache\Repository;
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
        $store = $this->lockStore();

        if ($store === null) {
            return $this->exchange($token, $leeway);
        }

        /** @var Lock $lock */
        $lock = $store->lock($this->lockKey($token), self::lockTtl());

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
     * The store the exchange is guarded in, or null if it cannot be guarded.
     *
     * The whole reason the exchange runs behind a lock is that the refresh
     * token rotates and may only be spent once. That promise is only as good as
     * the store the lock is taken in, and the store was being taken on faith:
     * one offering no atomic locks answered the call with a fatal error rather
     * than a lock, and one held in the memory of a single process answered with
     * a lock that no other process can see — which is not a lock at all in any
     * deployment running more than one worker, and `lock_store` is null by
     * default, so whatever the application caches in is what guards this.
     *
     * Neither is worth failing a sign-in over: a request that cannot take the
     * lock still has a token to renew, and refusing to renew it would sign the
     * user out over a cache setting. Both are said out loud instead — once per
     * process, because this sits on the hot path — and the exchange runs
     * unguarded, which is what it was already doing in the second case.
     *
     * A store that is shared but not in memory — Redis, Memcached, the
     * database — cannot be told apart from one that is not by looking at it,
     * so `file` on more than one server is left to the operator and to the note
     * on `lock_store` in the published configuration.
     */
    private function lockStore(): ?LockProvider
    {
        $configured = config('uzairports.lock_store');

        $repository = is_string($configured) && $configured !== ''
            ? Cache::store($configured)
            : Cache::store();

        // A lock is taken in the store, not in the repository wrapping it. A
        // repository that is itself a lock provider is accepted as one.
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
     * What has already been said about the lock store in this process.
     *
     * @var array<string, true>
     */
    private static array $reportedAboutTheLockStore = [];

    /**
     * Let the warnings be said again, for a suite that asserts on them.
     */
    public static function flushLockStoreWarnings(): void
    {
        self::$reportedAboutTheLockStore = [];
    }

    /**
     * Say a thing about the lock store once, however many requests notice it.
     *
     * This is read on every renewal, and a misconfigured store stays
     * misconfigured — so the line is worth writing once and worth nothing
     * repeated on every request that finds it.
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
                'oauth_error' => $this->oauthError($e),
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

    /**
     * The OAuth error code the identity provider refused the exchange with.
     *
     * The status alone does not say what went wrong. A refusal arrives as a 400
     * whether the grant is no longer honored — the login has to be made again —
     * or the request itself was wrong, which is a misconfiguration nobody can
     * act on without being told: same status, opposite remedies. RFC 6749 names
     * the difference in one field of the body, and it is the field an operator
     * reads the log for.
     *
     * Only the code is recorded. `error_description` is prose the provider
     * writes and may repeat the request back, which is a place a credential can
     * end up; the code is a fixed word from the specification and is not.
     */
    private function oauthError(Throwable $exception): ?string
    {
        if (! $exception instanceof RequestException) {
            return null;
        }

        $response = $exception->getResponse();

        if ($response === null) {
            return null;
        }

        $body = json_decode((string) $response->getBody(), true);

        if (! is_array($body)) {
            return null;
        }

        $error = $body['error'] ?? null;

        return is_string($error) && $error !== '' ? $error : null;
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
