<?php

namespace Uzairports\Uzairid\Actions;

use GuzzleHttp\Exception\RequestException;
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
     * The identity provider rotates the refresh token, so it may only be spent
     * once: two requests exchanging the same one would leave the loser holding a
     * token the provider has already invalidated. The exchange therefore runs
     * behind a lock, and whoever waited for it reads the token the winner stored
     * instead of spending it again — `$leeway` is the same margin the caller used
     * to decide the token needed renewing.
     *
     * Returns false when the SSO server refuses the exchange, in which case the
     * user has to authenticate again.
     *
     * An identity provider that has just failed to answer is left alone for a
     * moment first — see `providerIsUnreachable()`. That check comes before the
     * lock, because the waiting is the thing being spared: a request that would
     * only queue behind an exchange running out its own timeout is answered
     * from what is stored, or told to come back, without holding a worker for
     * either.
     *
     * @throws Throwable
     */
    public function __invoke(OauthToken $token, int $leeway = 0): bool
    {
        if ($this->providerIsUnreachable()) {
            return $this->answerWithoutCalling($token, $leeway);
        }

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
            return $this->answerWithoutCalling($token, $leeway);
        }
    }

    /**
     * Answer the caller from the row alone, without spending the refresh token.
     *
     * Both callers arrive here having decided not to make the exchange — one
     * waited out the request already making it, the other found the identity
     * provider not answering — and what is stored decides between the three
     * things that can be said. Somebody else may have renewed the login in the
     *  meantime or ended it; only where neither happened is the caller told to
     * come back.
     *
     * The 503 is deliberate, and so is what it is not. Answering `false` would
     * send the middleware on to end the login, which is to say that a provider
     * briefly unreachable would sign every one of its users out — and they
     * could not sign back in either, because signing in needs the same
     * provider. A grant that was never refused is kept.
     *
     * @throws ServiceUnavailableHttpException when the login is still due a renewal
     */
    private function answerWithoutCalling(OauthToken $token, int $leeway): bool
    {
        $adopted = $this->reload($token, $leeway);

        if ($adopted !== null) {
            return $adopted;
        }

        throw $this->temporarilyUnavailable();
    }

    /**
     * The entry saying the identity provider is being left alone.
     */
    private const string PROVIDER_FAILURE_KEY = 'uzairid:provider-unreachable';

    /**
     * The entry counting the failures that have not yet added up to an outage.
     */
    private const string PROVIDER_FAILURE_COUNT_KEY = 'uzairid:provider-failures';

    /**
     * Whether the identity provider is being left alone after a recent failure.
     *
     * Every renewal is its own lock and its own exchange, so nothing here
     * queues behind anything else: when the identity provider stops answering,
     * every request holding an expiring token pays the full request timeout on
     * its own before being told to come back, and one arriving behind a renewal
     * already running pays the lock wait on top. Those waits are held in
     * workers. There are far fewer workers than there are requests during a
     * wave of expiry — so an identity provider that is merely unreachable
     * took the whole application down with it, including every page that never
     * needed a token.
     *
     * Enough failures in a row therefore stand for the ones that would have
     * followed them. For `provider_cooldown` seconds afterward, the exchange is
     * not attempted at all, and the requests that would have queued are
     * answered from the row immediately — many of them by adopting a login
     * somebody else renewed just before the outage began.
     *
     * It takes `provider_failure_threshold` of them, not one. A single refusal
     * to answer is an ordinary thing — a dropped connection, a rate limit, a
     * response that arrived malformed — and it costs one request one timeout.
     * Standing every one of those up as an outage would be the worse bargain by
     * far: the whole application would stop renewing logins for a cooldown
     * every time the identity provider hiccuped, which is a self-inflicted
     * version of the failure this is here to prevent. An exchange that succeeds
     * clears the count, so blips never accumulate into one.
     *
     * There is no half-open probe: the entry simply lapses, traffic reaches the
     * provider again, and the first request to fail writes it back. That is why
     * the cooldown wants to be several times the request timeout — the window
     * in which traffic flows is one timeout long, so a cooldown shorter than
     * that spares almost nothing. The default is 30 seconds against a
     * 10-second timeout.
     *
     * The store is the one the lock is taken in, because this is the same
     * concern: what the processes serving the application do about one identity
     * provider. A store held in the memory of one process is worth having here
     * even so — unlike a lock, which guards nothing unless every process sees
     * it, this only ever spares work, and a process sparing its own is a real
     * saving. Nothing is said about such a store because nothing is wrong with
     * it.
     */
    private function providerIsUnreachable(): bool
    {
        if (self::providerCooldown() === 0) {
            return false;
        }

        try {
            return $this->breakerCache()?->has(self::PROVIDER_FAILURE_KEY) === true;
        } catch (Throwable) {
            // A renewal is never refused over a cache setting. A store that
            // cannot be read simply has nothing to say about the provider.
            return false;
        }
    }

    /**
     * Count one failure and leave the provider alone once they add up.
     *
     * Only a provider that did not answer is counted. One that refused the
     * grant answered perfectly well — that login is over, and the next request
     * has to reach the provider to start a new one.
     *
     * The count is given the cooldown's own lifetime, so failures spread wider
     * apart than that never meet. `add()` before `increment()` is what puts a
     * lifetime on it completely: incrementing a key that is not there creates one
     * that outlives every window on some stores.
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
            // Nothing here is worth failing a renewal over either: without the
            //  entry, the next request simply makes the call this one made.
        }
    }

    /**
     * Take back what has been counted against the identity provider.
     *
     * An exchange that succeeded is the whole answer to the question the count
     * was asking, so the failures behind it are dropped rather than left to
     * lapse: a provider that fails once an hour must never reach the threshold,
     * however, long it stays up in between.
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
            // A store that will not answer has nothing recorded in it either.
        }
    }

    /**
     * How many failures within a cooldown make an outage.
     *
     * One is allowed and means the first failure stands for the outage.
     */
    private static function providerFailureThreshold(): int
    {
        $configured = config('uzairports.provider_failure_threshold', 5);

        return max(is_numeric($configured) ? (int) $configured : 5, 1);
    }

    /**
     * Let the identity provider be called again at once.
     *
     * The entry lapses on its own, so this is for an operator who has just
     * fixed the provider and for a suite that asserts on the cooldown.
     */
    public static function forgetProviderFailure(): void
    {
        try {
            $cache = (new self)->breakerCache();

            $cache?->forget(self::PROVIDER_FAILURE_COUNT_KEY);
            $cache?->forget(self::PROVIDER_FAILURE_KEY);
        } catch (Throwable) {
            // Nothing to forget in a store that will not answer.
        }
    }

    /**
     * How long the identity provider is left alone after it fails to answer.
     *
     * Zero switches it off, which is the behavior of calling the provider on
     * every renewal, however, it answered the last one.
     */
    private static function providerCooldown(): int
    {
        $configured = config('uzairports.provider_cooldown', 30);

        return max(is_numeric($configured) ? (int) $configured : 30, 0);
    }

    /**
     * What `lock_store` names, resolved once for the life of this action.
     *
     * The lock and the note about the identity provider are the same concern
     * and live in the same store. One renewal asks for it up to three times
     * — before the lock, for the lock, and again if the exchange fails.
     * Resolving a store is inexpensive but not free, and it is the same store every
     * time, so it is asked for once.
     *
     * The type is what the facade promises rather than what it returns: a host
     * application is free to bind something else, and both readers below check
     * what they were actually handed before using it.
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
     * The store the note about the identity provider is kept in.
     *
     * Null where what `lock_store` names cannot hold an entry at all — a bare
     * lock provider, or whatever else a host application has bound. The
     * cooldown is given up rather than insisted on; see `providerIsUnreachable()`
     * for why nothing here is worth refusing a renewal over.
     */
    private function breakerCache(): ?CacheRepository
    {
        $repository = $this->configuredStore();

        return $repository instanceof CacheRepository ? $repository : null;
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
        $repository = $this->configuredStore();

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
     *
     * Reached between requests on a long-lived runtime through
     * `Uzair::flushState()`, which is where the reason is written down.
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
                'http_status' => $e instanceof RequestException ? $e->getResponse()?->getStatusCode() : null,
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
     * The driver this exchange is made through.
     *
     * `Socialite::driver('uzairports')` hands back whatever is registered under
     * that name, and a host application is free to register something else —
     * the annotation that used to stand here promised a type nobody checked.
     * What arrived instead reached `refreshToken()` and raised an `Error`,
     * which the exchange caught as an ordinary failure: the login was left
     * being renewed on every request, answered 503 every time, and the log said
     * the identity provider had failed to refresh a token it was never asked
     * about. `EndSessions::revokeAll()` already refuses a driver of the wrong
     * type by name; this says the same thing at the other end.
     *
     * A 503 rather than `false`, for the reason `answerWithoutCalling()` gives:
     * ending the login over this would sign every user out of an application
     * that cannot sign them back in until somebody fixes the registration.
     *
     * The provider is not recorded as unreachable. It was never called, and a
     * cooldown would only postpone the log line an operator needs to read.
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
     * Say which driver was found where this package's was expected.
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

    /**
     * The OAuth error codes that name the application rather than the login.
     *
     * RFC 6749 §5.2 gives both to the client, not to the grant it presented:
     * `invalid_client` is credentials the identity provider would not
     * authenticate, and `unauthorized_client` is a client not allowed to use
     * this grant type at all. Neither says anything about the refresh token —
     * every login of every account gets the same answer, because there is one
     * set of credentials behind all of them.
     *
     * They used to be read as a refused grant, which is the one answer that
     * must never be given here: `false` sends the middleware on to end the
     * login, so a mistyped `client_secret` signed every user out as their
     * tokens came due — and none of them could sign back in, since starting a
     * new login spends the same credentials. That is the failure
     * `answerWithoutCalling()` and `refuseTheDriver()` already refuse to cause;
     * this is the third door into it.
     *
     * @var list<string>
     */
    private const array CLIENT_ERRORS = ['invalid_client', 'unauthorized_client'];

    /**
     * Say that the application, not the login, is what was refused.
     *
     * A 503 rather than `false`, and an error rather than the warning the
     * exchange already wrote: nothing renews until somebody changes the
     * configuration, and the line that says so is the one an operator is
     * looking for.
     *
     * The provider is not recorded as unreachable. It answered, and precisely —
     * the cooldown is for a provider that did not, and pausing the calls here
     * would only postpone the log line while the logins stay stuck either way.
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
     * Whether the identity provider refused the grant this login presented.
     *
     * Only the login is ended on this answer, so it covers the codes that name
     * the grant and nothing else. What names the application is taken out
     * before this is asked — see `CLIENT_ERRORS`.
     *
     * A refusal whose body cannot be read is still a refusal at 401, and stays
     * one: the token endpoint answering 401 with no OAuth error to give is the
     * shape of a credential that is no longer honored.
     */
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
