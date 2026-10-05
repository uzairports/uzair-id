<?php

namespace Uzairports\Uzairid\Actions;

use GuzzleHttp\Exception\BadResponseException;
use GuzzleHttp\Promise\Each;
use GuzzleHttp\Promise\PromiseInterface;
use Illuminate\Database\Query\Builder;
use Illuminate\Session\ArraySessionHandler;
use Illuminate\Session\CookieSessionHandler;
use Illuminate\Support\Collection as SupportCollection;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Session;
use Laravel\Socialite\Facades\Socialite;
use RuntimeException;
use SessionHandlerInterface;
use Throwable;
use Uzairports\Uzairid\Models\OauthToken;
use Uzairports\Uzairid\Socialite\UzairportsProvider;
use Uzairports\Uzairid\Uzair;

class EndSessions
{
    /**
     * End the account's logins, optionally sparing one.
     *
     * Ending a login does three things:
     *
     * - revokes its grants at UzAirports ID, so the identity provider cannot
     *   silently sign the device back in;
     * - deletes the row, so `uzair.token` refuses the session on its next request;
     * - drops the stored session (database table or session handler) and, for a
     *   mobile login, its Sanctum token, so routes without `uzair.token` refuse it too.
     *
     * `$exceptSessionId` spares the current browser; `$exceptLoginId` spares one
     * login by its row, which is how a mobile client is spared.
     *
     * With `$revoke`, rows are deleted one by one so model events fire, and only
     * rows that actually deleted have their grants revoked: a row a `deleting`
     * observer refuses keeps its grant. With `$revoke = false` the rows go in a
     * single statement without hydrating models or decrypting credentials; this
     * path is deliberately invisible to model observers. The local sign-out
     * happens either way.
     *
     * @return int the number of logins ended
     *
     * @throws Throwable
     */
    public function __invoke(int|string $userId, ?string $exceptSessionId = null, bool $revoke = true, int|string|null $exceptLoginId = null): int
    {
        $query = OauthToken::query()
            ->where('user_id', $userId)
            ->when($exceptSessionId !== null, fn ($query) => $query->where(
                fn ($q) => $q->whereNull('session_id')->orWhere('session_id', '!=', $exceptSessionId)
            ))
            ->when($exceptLoginId !== null, fn ($query) => $query->whereKeyNot($exceptLoginId));

        if (! $revoke) {
            $rows = $query->getModel()->getConnection()->transaction(function () use ($query): SupportCollection {
                $rows = (clone $query)->orderBy('id')->lockForUpdate()->toBase()->get(['id', 'session_id', 'personal_access_token_id']);

                if ($rows->isNotEmpty()) {
                    (clone $query)->whereKey($rows->pluck('id')->all())->delete();
                }

                return $rows;
            });

            $sessionIds = [];

            foreach ($rows->pluck('session_id') as $rawSessionId) {
                if (is_string($rawSessionId) && $rawSessionId !== '') {
                    $sessionIds[] = $rawSessionId;
                }
            }

            $this->deleteStoredSessionsById($sessionIds);
            $this->forgetResolvedLogins($sessionIds);
            $this->dropAccessTokens($rows->pluck('personal_access_token_id')->all());

            return $rows->count();
        }

        $tokens = $query->getModel()->getConnection()->transaction(function () use ($query): SupportCollection {
            $locked = $query
                ->orderBy('id')
                ->lockForUpdate()
                ->get(['id', 'user_id', 'session_id', 'personal_access_token_id', 'access_token', 'refresh_token']);

            // One delete per row so model events fire; only deleted rows are revoked.
            return $locked
                ->filter(fn (OauthToken $token): bool => $token->delete() === true)
                ->values();
        });

        $sessionIds = [];

        foreach ($tokens as $token) {
            $sessionId = $token->session_id;
            if (is_string($sessionId) && $sessionId !== '') {
                $sessionIds[] = $sessionId;
            }
        }

        // The rows are already deleted, so revocation must run even if cleanup fails.
        try {
            $this->deleteStoredSessionsById($sessionIds);
            $this->forgetResolvedLogins($sessionIds);
            $this->dropAccessTokens($tokens->pluck('personal_access_token_id')->all());
        } finally {
            $this->revokeAll($tokens);
        }

        return $tokens->count();
    }

    /**
     * Refuse the login locally before submitting remote revocation.
     *
     * @throws Throwable
     */
    public function end(OauthToken $token): void
    {
        $this->endAll([$token]);
    }

    /**
     * End several named logins, revoking all of their grants in one batch.
     *
     * Each row is deleted on its own so model events fire. Session ids are
     * deduplicated, since rows of different accounts may share one. Cleanup and
     * revocation still run for rows already deleted if a later deletion throws.
     *
     * @param  iterable<array-key, OauthToken>  $tokens
     *
     * @throws Throwable
     */
    public function endAll(iterable $tokens): void
    {
        /** @var list<OauthToken> $ended */
        $ended = [];

        /** @var array<string, true> $sessionIds */
        $sessionIds = [];

        /** @var list<int|string> $accessTokenIds */
        $accessTokenIds = [];

        try {
            foreach ($tokens as $token) {
                $deleted = $token->getConnection()->transaction(function () use ($token): bool {
                    $stored = $token->newQuery()->whereKey($token->getKey())->lockForUpdate()->first();

                    if ($stored === null) {
                        return false;
                    }

                    $token->setRawAttributes($stored->getAttributes(), sync: true);

                    return $token->delete() === true;
                });

                if (! $deleted) {
                    continue;
                }

                $sessionId = $token->session_id;

                if (is_string($sessionId) && $sessionId !== '') {
                    $sessionIds[$sessionId] = true;
                }

                if ($token->personal_access_token_id !== null) {
                    $accessTokenIds[] = $token->personal_access_token_id;
                }

                $ended[] = $token;
            }
        } finally {
            if ($ended !== []) {
                try {
                    $this->deleteStoredSessionsById(array_keys($sessionIds));
                    $this->forgetResolvedLogins(array_keys($sessionIds));
                    $this->dropAccessTokens($accessTokenIds);
                } finally {
                    $this->revokeAll($ended);
                }
            }
        }
    }

    /**
     * Forget the cached logins of the ended sessions.
     *
     * Otherwise `uzair.token` keeps trusting the cache until it expires. Cache
     * failures are reported by the model, never raised.
     *
     * @param  array<array-key, string>  $sessionIds
     */
    private function forgetResolvedLogins(array $sessionIds): void
    {
        OauthToken::forgetLogins($sessionIds);
    }

    /**
     * Delete the Sanctum tokens the ended logins were issued under.
     *
     * Deleted by key in one statement through the application's Sanctum token
     * model; a no-op without Sanctum. Failures are reported, never raised, so
     * revocation is not skipped.
     *
     * @param  array<array-key, mixed>  $accessTokenIds
     */
    public function dropAccessTokens(array $accessTokenIds): void
    {
        $accessTokenIds = array_values(array_unique(array_filter(
            $accessTokenIds,
            fn (mixed $id): bool => is_int($id) || (is_string($id) && $id !== ''),
        )));

        $model = Uzair::accessTokenModel();

        if ($accessTokenIds === [] || $model === null) {
            return;
        }

        try {
            $model::query()->whereKey($accessTokenIds)->delete();
        } catch (Throwable $e) {
            Log::warning('Failed to delete the Sanctum token of an ended UzAirports login.', [
                'exception_class' => $e::class,
            ]);
        }
    }

    /**
     * Revoke a login's grants at the identity provider, leaving the row alone.
     *
     * Used by pruning, which deletes the row itself.
     */
    public function surrender(OauthToken $token): void
    {
        $this->surrenderAll([$token]);
    }

    /**
     * Revoke grants that were issued but never stored.
     *
     * Called when sign-in fails after the code exchange (profile request, or
     * writing the account or login), since no row exists for anything to end.
     * The values go onto an unsaved model only because revocation reads them
     * from one; nothing is written.
     */
    public function surrenderIssued(mixed $accessToken, mixed $refreshToken): void
    {
        $grants = array_filter(
            ['access_token' => $accessToken, 'refresh_token' => $refreshToken],
            fn (mixed $grant): bool => is_string($grant) && $grant !== '',
        );

        if ($grants === []) {
            return;
        }

        $this->surrender((new OauthToken)->forceFill($grants));
    }

    /**
     * Revoke several logins' grants in one batch, leaving their rows alone.
     *
     * @param  iterable<array-key, OauthToken>  $tokens
     */
    public function surrenderAll(iterable $tokens): void
    {
        $this->revokeAll($tokens);
    }

    /**
     * Revoke every grant concurrently and wait once for all of them.
     *
     * Up to `revocation_concurrency` requests are in flight at a time. Grants
     * that cannot be decrypted are skipped, and the driver is not resolved when
     * none are readable. Failures are reported, never raised.
     *
     * @param  iterable<array-key, OauthToken>  $tokens
     */
    private function revokeAll(iterable $tokens): void
    {
        /** @var list<array{token: OauthToken, access: string|null, refresh: string|null}> $grants */
        $grants = [];

        foreach ($tokens as $token) {
            $accessToken = $token->readableAccessToken();
            $refreshToken = $token->readableRefreshToken();

            if ($accessToken === null && $refreshToken === null) {
                continue;
            }

            $grants[] = ['token' => $token, 'access' => $accessToken, 'refresh' => $refreshToken];
        }

        if ($grants === []) {
            return;
        }

        try {
            $provider = Socialite::driver('uzairports');
        } catch (Throwable $exception) {
            foreach ($grants as $grant) {
                $this->reportFailedRevocation($grant['token'], $exception);
            }

            return;
        }

        // A foreign driver is reported, not raised: a logout must never answer with a 500.
        if (! $provider instanceof UzairportsProvider) {
            $misconfigured = new RuntimeException('The [uzairports] Socialite driver is not '.UzairportsProvider::class.'.');

            foreach ($grants as $grant) {
                $this->reportFailedRevocation($grant['token'], $misconfigured);
            }

            return;
        }

        /** @var list<array{token: OauthToken, access: string|null, refresh: string|null}> $requests */
        $requests = [];

        foreach ($grants as $grant) {
            if ($grant['access'] !== null) {
                $requests[] = ['token' => $grant['token'], 'access' => $grant['access'], 'refresh' => null];
            }

            if ($grant['refresh'] !== null) {
                $requests[] = ['token' => $grant['token'], 'access' => null, 'refresh' => $grant['refresh']];
            }
        }

        foreach (array_chunk($requests, $this->revocationConcurrency()) as $chunk) {
            $this->settle($provider, $chunk);
        }
    }

    /**
     * Send one batch of revocations and settle them together.
     *
     * One failure neither hides nor cancels the rest. A 401 on an access token
     * means it is already invalid and is not logged; a 401 on a refresh token
     * is, because that endpoint answers 200 for already-retired tokens.
     *
     * @param  list<array{token: OauthToken, access: string|null, refresh: string|null}>  $grants
     */
    private function settle(UzairportsProvider $provider, array $grants): void
    {
        /** @var list<PromiseInterface> $promises */
        $promises = [];

        /** @var list<array{token: OauthToken, spareUnauthorized: bool}> $sent */
        $sent = [];

        foreach ($grants as $grant) {
            if ($grant['access'] !== null) {
                $promise = $this->send(fn (): ?PromiseInterface => $provider->logoutAsync($grant['access']), $grant['token']);

                if ($promise !== null) {
                    $promises[] = $promise;
                    $sent[] = ['token' => $grant['token'], 'spareUnauthorized' => true];
                }
            }

            if ($grant['refresh'] !== null) {
                $promise = $this->send(fn (): ?PromiseInterface => $provider->revokeRefreshTokenAsync($grant['refresh']), $grant['token']);

                if ($promise !== null) {
                    $promises[] = $promise;
                    $sent[] = ['token' => $grant['token'], 'spareUnauthorized' => false];
                }
            }
        }

        if ($promises === []) {
            return;
        }

        Each::of($promises, null, function (mixed $reason, int $index) use ($sent): void {
            if (! $reason instanceof Throwable || ! isset($sent[$index])) {
                return;
            }

            $unauthorized = $reason instanceof BadResponseException && $reason->getResponse()->getStatusCode() === 401;

            if ($sent[$index]['spareUnauthorized'] && $unauthorized) {
                return;
            }

            $this->reportFailedRevocation($sent[$index]['token'], $reason);
        })->wait();
    }

    /**
     * Start one revocation; null when there is no endpoint or the call failed (and was logged).
     *
     * @param  callable(): (PromiseInterface|null)  $start
     */
    private function send(callable $start, OauthToken $token): ?PromiseInterface
    {
        try {
            return $start();
        } catch (Throwable $exception) {
            $this->reportFailedRevocation($token, $exception);

            return null;
        }
    }

    /**
     * How many revocations may be in flight at once.
     *
     * Values below 1 fall back to 1.
     *
     * @return int<1, max>
     */
    private function revocationConcurrency(): int
    {
        $configured = config('uzairports.revocation_concurrency', 10);
        $concurrency = is_numeric($configured) ? (int) $configured : 10;

        return $concurrency < 1 ? 1 : $concurrency;
    }

    private function reportFailedRevocation(OauthToken $token, Throwable $exception): void
    {
        Log::warning('Failed to revoke an UzAirports token.', [
            'user_id' => $token->user_id,
            'exception_class' => $exception::class,
            'http_status' => $exception instanceof BadResponseException ? $exception->getResponse()->getStatusCode() : null,
        ]);
    }

    /**
     * Drop the named sessions from the session store.
     *
     * The database driver's sessions go in one statement (ids deduplicated);
     * every other driver is reached through its handler's `destroy()`.
     *
     * The array and cookie handlers are skipped: the array handler holds only
     * this process's sessions, and the cookie handler's `destroy()` would queue
     * a cookie onto the current browser's response, not the one being signed out.
     *
     * Failures are reported once per batch, never raised, so revocation is not skipped.
     *
     * @param  array<array-key, string>  $sessionIds
     */
    private function deleteStoredSessionsById(array $sessionIds): void
    {
        $sessionIds = array_values(array_unique(array_filter(
            $sessionIds,
            fn (string $sessionId): bool => $sessionId !== '',
        )));

        if ($sessionIds === []) {
            return;
        }

        if (config('session.driver') === 'database') {
            try {
                $this->storedSessions()->whereIn('id', $sessionIds)->delete();
            } catch (Throwable $e) {
                Log::warning('Failed to delete the stored session of an UzAirports user.', [
                    'exception_class' => $e::class,
                ]);
            }

            return;
        }

        $handler = $this->sessionHandler();

        if ($handler === null) {
            return;
        }

        $failure = null;

        foreach ($sessionIds as $sessionId) {
            try {
                $handler->destroy($sessionId);
            } catch (Throwable $e) {
                $failure ??= $e;
            }
        }

        if ($failure !== null) {
            Log::warning('Failed to drop the stored session of an UzAirports user from the session store.', [
                'session_driver' => config('session.driver'),
                'exception_class' => $failure::class,
            ]);
        }
    }

    /**
     * The handler holding other browsers' sessions.
     *
     * Null for the array and cookie handlers, or when no session manager can be
     * built (e.g. a console command in an app without sessions).
     */
    private function sessionHandler(): ?SessionHandlerInterface
    {
        try {
            $handler = Session::getHandler();
        } catch (Throwable) {
            return null;
        }

        if ($handler instanceof ArraySessionHandler || $handler instanceof CookieSessionHandler) {
            return null;
        }

        return $handler;
    }

    /**
     * A query against the table the session store keeps its rows in.
     */
    private function storedSessions(): Builder
    {
        $connection = config('session.connection');
        $table = config('session.table', 'sessions');

        return DB::connection(is_string($connection) ? $connection : null)
            ->table(is_string($table) ? $table : 'sessions');
    }
}
