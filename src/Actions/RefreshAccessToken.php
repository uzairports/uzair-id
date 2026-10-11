<?php

namespace Uzairports\Uzairid\Actions;

use GuzzleHttp\Exception\BadResponseException;
use GuzzleHttp\Exception\GuzzleException;
use Illuminate\Cache\ArrayStore;
use Illuminate\Cache\Repository;
use Illuminate\Contracts\Cache\Lock;
use Illuminate\Contracts\Cache\LockProvider;
use Illuminate\Contracts\Cache\LockTimeoutException;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Log;
use JsonException;
use Laravel\Socialite\Facades\Socialite;
use Laravel\Socialite\Two\Token;
use RuntimeException;
use Symfony\Component\HttpKernel\Exception\ServiceUnavailableHttpException;
use Throwable;
use Uzairports\Uzairid\Events\UzairTokenRefreshed;
use Uzairports\Uzairid\Events\UzairTokenRefreshFailed;
use Uzairports\Uzairid\Models\OauthToken;
use Uzairports\Uzairid\Socialite\UzairportsProvider;
use Uzairports\Uzairid\Support\ProviderCircuitBreaker;
use Uzairports\Uzairid\Support\TokenExpiry;

class RefreshAccessToken
{
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
     * Lock store warnings already logged in this process.
     *
     * @var array<string, true>
     */
    private static array $reportedAboutTheLockStore = [];

    /**
     * The `lock_store` store, resolved once and shared by the lock and the
     * breaker.
     *
     * Typed `mixed` because a host may bind anything; `lockStore()` and the
     * breaker check what they receive.
     */
    private mixed $configuredStore = null;

    private bool $storeWasResolved = false;

    private ?ProviderCircuitBreaker $breaker = null;

    /**
     * Exchange the stored refresh token for a fresh access token.
     *
     * The provider rotates refresh tokens, so each may be spent only once. The
     * exchange runs behind a lock; a request that waited reads the token the
     * winner stored instead of spending it again. `$leeway` is the margin the
     * caller used to decide the token needed renewing.
     *
     * Returns false when the provider refuses the grant; the user must sign in
     * again. The cooldown check (`ProviderCircuitBreaker::isOpen()`) runs before
     * the lock so that requests do not hold workers waiting on a failing
     * provider. A lock store failure is answered from the row, never by
     * exchanging unguarded, while failures from the exchange itself propagate
     * to the caller untouched.
     *
     * @throws Throwable
     */
    public function __invoke(OauthToken $token, int $leeway = 0): bool
    {
        if ($this->breaker()->isOpen()) {
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
            if ($this->breaker()->isOpen()) {
                return $this->answerWithoutCalling($token, $leeway);
            }

            return $this->exchange($token, $leeway);
        } finally {
            $this->release($lock);
        }
    }

    /**
     * End the cooldown immediately (for operators and tests).
     */
    public static function forgetProviderFailure(): void
    {
        (new self)->breaker()->reset();
    }

    /**
     * Allow lock store warnings to be logged again; called from
     * `Uzair::flushState()` and by tests.
     */
    public static function flushLockStoreWarnings(): void
    {
        self::$reportedAboutTheLockStore = [];
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
     * The cooldown kept for the identity provider, sharing the `lock_store`
     * store with the lock. The store is resolved only when the breaker first
     * reads it, inside its own `try`.
     */
    private function breaker(): ProviderCircuitBreaker
    {
        return $this->breaker ??= new ProviderCircuitBreaker(fn (): mixed => $this->configuredStore());
    }

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
     * Only a failure to reach or understand the provider — Guzzle's transport
     * and HTTP errors, a body that is not JSON, the driver's `RuntimeException`
     * over a malformed token response — is answered as a failed exchange. Any
     * other exception is a programming error: it is announced through
     * `UzairTokenRefreshFailed` and rethrown untouched, neither counted toward
     * the cooldown nor dressed up as a 503.
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
        } catch (GuzzleException|JsonException|RuntimeException $exception) {
            return $this->answerFailedExchange($token, $exception);
        } catch (Throwable $exception) {
            UzairTokenRefreshFailed::dispatch($token, $exception);

            throw $exception;
        }

        $this->breaker()->recordSuccess();

        if (blank($refreshed->token)) {
            Log::warning('UzAirports refresh token exchange returned empty access token', [
                'user_id' => $token->user_id,
            ]);

            UzairTokenRefreshFailed::dispatch($token);

            throw $this->temporarilyUnavailable();
        }

        $token->forceFill([
            'access_token' => $refreshed->token,
            'refresh_token' => $refreshed->refreshToken ?: $refreshToken,
            'expires_at' => TokenExpiry::fromExpiresIn($refreshed->expiresIn),
        ]);

        // The exchange stays outside the transaction. Logout and a repeated
        // sign-in take this same row lock before reading the grants they will
        // replace, delete or surrender.
        $superseding = null;

        try {
            $saved = $token->getConnection()->transaction(function () use ($token, $refreshToken, &$superseding): bool {
                $stored = $token->newQuery()->whereKey($token->getKey())->lockForUpdate()->first();

                if ($stored === null) {
                    return false;
                }

                if ($stored->readableRefreshToken() !== $refreshToken) {
                    $superseding = $stored;

                    return false;
                }

                return $token->save();
            });
        } catch (Throwable $exception) {
            $this->surrenderIssuedGrants($refreshed, $refreshToken);
            UzairTokenRefreshFailed::dispatch($token, $exception);

            throw $exception;
        }

        if ($superseding instanceof OauthToken) {
            return $this->adoptSupersedingGrants($token, $superseding, $refreshed, $refreshToken);
        }

        if (! $saved) {
            $this->surrenderIssuedGrants($refreshed, $refreshToken);
            UzairTokenRefreshFailed::dispatch($token);

            return false;
        }

        UzairTokenRefreshed::dispatch($token);

        return true;
    }

    /**
     * Answer an exchange the provider failed or refused.
     *
     * Returns false for a refused grant, which ends the login. Everything else
     * is a 503: `CLIENT_ERRORS` without touching the cooldown, an answer about
     * the provider itself (no answer, 5xx, 429) after counting toward it.
     *
     * @throws ServiceUnavailableHttpException unless the grant was refused
     */
    private function answerFailedExchange(OauthToken $token, GuzzleException|JsonException|RuntimeException $exception): bool
    {
        $statusCode = $exception instanceof BadResponseException ? $exception->getResponse()->getStatusCode() : null;
        $body = $exception instanceof BadResponseException ? $this->decodedBody($exception) : null;
        $oauthError = $this->oauthError($body);

        Log::warning('Failed to refresh UzAirports access token.', [
            'user_id' => $token->user_id,
            'exception_class' => $exception::class,
            'http_status' => $statusCode,
            'oauth_error' => $oauthError,
        ]);

        UzairTokenRefreshFailed::dispatch($token, $exception);

        if ($oauthError !== null && in_array($oauthError, self::CLIENT_ERRORS, true)) {
            $this->refuseTheClient($token, $oauthError);
        }

        if ($this->grantWasRejected($statusCode, $body)) {
            return false;
        }

        if ($this->providerFailed($statusCode)) {
            $this->breaker()->recordFailure();
        }

        throw $this->temporarilyUnavailable();
    }

    /**
     * Give up this exchange's grants for the ones written while it was out.
     *
     * The row no longer holds the refresh token that was spent: the browser
     * signed in again on the same session, and `RecordLogin` wrote that sign-in's
     * grants and surrendered the spent ones. Saving over it would leave the new
     * sign-in's grants with no row pointing at them, honored at the identity
     * provider and never surrendered. The newer login stands instead.
     */
    private function adoptSupersedingGrants(OauthToken $token, OauthToken $stored, Token $refreshed, string $spentRefreshToken): bool
    {
        $this->surrenderIssuedGrants($refreshed, $spentRefreshToken);

        $token->setRawAttributes($stored->getAttributes(), sync: true);

        return true;
    }

    /**
     * Whether a failed exchange counts toward the provider's cooldown.
     *
     * Only an answer that says the provider itself is in trouble does: no
     * answer at all (no status), a 5xx, or a 429. Any other 4xx is the provider
     * answering about this one request — a malformed or legacy grant on one
     * account — and five of those within a cooldown would otherwise stop every
     * login in the application from renewing.
     */
    private function providerFailed(?int $statusCode): bool
    {
        return $statusCode === null || $statusCode >= 500 || $statusCode === 429;
    }

    /**
     * Revoke only the grants this exchange issued.
     *
     * A provider that does not rotate the refresh token answers with none, or
     * with the one just spent. The stored row still holds that token, so
     * surrendering it over a failed write would end a login that should
     * have survived.
     */
    private function surrenderIssuedGrants(Token $refreshed, string $spentRefreshToken): void
    {
        $issuedRefreshToken = $refreshed->refreshToken !== $spentRefreshToken
            ? $refreshed->refreshToken
            : null;

        app(EndSessions::class)->surrenderIssued($refreshed->token, $issuedRefreshToken);
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
     * The JSON object a refused exchange answered with, read once for both
     * `oauthError()` and `grantWasRejected()`; null when it is not one.
     *
     * @return array<array-key, mixed>|null
     */
    private function decodedBody(BadResponseException $exception): ?array
    {
        $body = json_decode((string) $exception->getResponse()->getBody(), true);

        return is_array($body) ? $body : null;
    }

    /**
     * The RFC 6749 `error` code from a refused exchange, if any.
     *
     * A 400 can mean a dead grant or a misconfigured client; the code tells
     * them apart. `error_description` is deliberately not read, as it may echo
     * request data including credentials.
     *
     * @param  array<array-key, mixed>|null  $body
     */
    private function oauthError(?array $body): ?string
    {
        $error = $body['error'] ?? null;

        return is_string($error) && $error !== '' ? $error : null;
    }

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
     *
     * @param  array<array-key, mixed>|null  $body
     */
    private function grantWasRejected(?int $statusCode, ?array $body): bool
    {
        if ($statusCode !== 400 && $statusCode !== 401) {
            return false;
        }

        if ($body === null) {
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
