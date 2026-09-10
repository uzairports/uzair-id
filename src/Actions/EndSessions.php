<?php

namespace Uzairports\Uzairid\Actions;

use GuzzleHttp\Exception\RequestException;
use GuzzleHttp\Promise\PromiseInterface;
use GuzzleHttp\Promise\Utils;
use Illuminate\Database\Query\Builder;
use Illuminate\Support\Collection as SupportCollection;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;
use Laravel\Socialite\Facades\Socialite;
use RuntimeException;
use Throwable;
use Uzairports\Uzairid\Models\OauthToken;
use Uzairports\Uzairid\Socialite\UzairportsProvider;

class EndSessions
{
    /**
     * End the account's logins, optionally sparing one.
     *
     * Three things have to go for a device to actually be signed out, and each
     * covers a gap the others leave:
     *
     * - The token is revoked at UzAirports ID. Without this the device is only
     *   sent back through `login`, where the identity provider — which still
     *   holds a session for that browser — answers with a fresh authorization
     *   code and lets it straight back in;
     * - The row is deleted, so `uzair.token` refuses that session on its next
     *   request whatever the session driver is;
     * - The session itself is deleted from the store, so a device that never
     *   reaches the middleware loses its session too. Only the database driver
     *   keeps sessions somewhere this can reach.
     *
     * Pass `$exceptSessionId` to keep the browser in front of you signed in.
     *
     * `$revoke` is the one part of this that costs a round-trip. The grants go
     * out together rather than one after the next — see `revokeAll()` — so the
     * wait is the slowest of them and not the sum, but it is still a wait on an
     * identity provider, and there is no telling in advance how many logins an
     * account holds. Where it is being paid by a browser — signing in under
     * `single_session` — it can be given up. The first two steps still happen,
     * so the account is signed out here either way; what is surrendered is the
     * promise that its grants stop being honored at UzAirports ID before they
     * expire on their own.
     *
     * On the revoking path the rows are deleted one apiece, the way `endAll()`
     * and the pruning sweep delete them, so anything observing the model hears
     * about every login that ends here. It used to be one statement for all of
     * them, which is an Eloquent builder delete and fires nothing: an
     * application auditing logouts through an observer saw every ending except
     * the ones `single_session` made, which are the ones nobody asked for and
     * so the ones most worth hearing about. The models are hydrated for their
     * grants anyway, so what this costs is a statement per row inside the one
     * transaction already holding them all locked.
     *
     * A row a `deleting` observer refuses is left standing, and its grant is
     * not surrendered — the login is still there to spend it.
     *
     * When revocation is declined, there are no models at all: the rows go in
     * one statement, and the session ids are plucked without hydrating Eloquent
     * or decrypting a credential. That is the whole point of asking for that
     * path, and it is the one ending in this package that model observers do
     * not hear about.
     *
     * @return int the number of logins ended
     *
     * @throws Throwable
     */
    public function __invoke(int|string $userId, ?string $exceptSessionId = null, bool $revoke = true): int
    {
        $query = OauthToken::query()
            ->where('user_id', $userId)
            ->when($exceptSessionId !== null, fn ($query) => $query->where(
                fn ($q) => $q->whereNull('session_id')->orWhere('session_id', '!=', $exceptSessionId)
            ));

        if (! $revoke) {
            $rows = $query->getModel()->getConnection()->transaction(function () use ($query): SupportCollection {
                $rows = (clone $query)->orderBy('id')->lockForUpdate()->toBase()->get(['id', 'session_id']);

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

            $this->deleteStoredSessions($userId, $exceptSessionId, $sessionIds);
            $this->forgetResolvedLogins($sessionIds);

            return $rows->count();
        }

        $tokens = $query->getModel()->getConnection()->transaction(function () use ($query): SupportCollection {
            $locked = $query
                ->orderBy('id')
                ->lockForUpdate()
                ->get(['id', 'user_id', 'session_id', 'access_token', 'refresh_token']);

            // Deleted one apiece so the model's own events fire, and only what
            // actually went is carried out of the transaction: a row an
            // observer refused still holds its grant.
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

        // The rows are committed by the time this runs, so the grants they held
        // have nothing left pointing at them: whatever the cleanup before it
        // does, the revocation is the last chance to stop the identity provider
        // honoring them. `endAll()` holds the same guarantee the same way.
        try {
            $this->deleteStoredSessions($userId, $exceptSessionId, $sessionIds);
            $this->forgetResolvedLogins($sessionIds);
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
     * End several named logins, paying one wait for all of their grants.
     *
     * `end()` in a loop would settle each login's revocations on its own, so a
     * caller holding a handful of rows waited out one batch after the next when
     * none of those calls decides any of the others. Here the rows go first —
     * each by its own delete, so anything observing the model still hears about
     * it — and every grant they held is handed back together.
     *
     * The sessions they named are dropped in one statement rather than one
     * apiece, and a session named twice is dropped once: rows found by session
     * id may belong to different accounts, and the same id would otherwise be
     * deleted from the store as many times as there are accounts holding it.
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

                $ended[] = $token;
            }
        } finally {
            if ($ended !== []) {
                try {
                    $this->deleteStoredSessionsById(array_keys($sessionIds));
                    $this->forgetResolvedLogins(array_keys($sessionIds));
                } finally {
                    $this->revokeAll($ended);
                }
            }
        }
    }

    /**
     * Stop the ended logins standing in for rows that are no longer there.
     *
     * `uzair.token` may let a request through on what it last resolved for a
     * session, so a login ended here has to take that answer with it — the
     * device would otherwise keep being let through until the entry lapsed.
     *
     * The model reports a store that will not answer rather than raising it:
     * the rows are already gone by the time any caller reaches this, and what
     * follows — dropping the sessions, surrendering the grants — must not be
     * skipped over a cache.
     *
     * @param  array<array-key, string>  $sessionIds
     */
    private function forgetResolvedLogins(array $sessionIds): void
    {
        OauthToken::forgetLogins($sessionIds);
    }

    /**
     * Give a login's grant up at the identity provider, leaving the row alone.
     *
     * This is what pruning needs. The sweep deletes the row itself. The
     * store collected the session it named long before the sweep
     * reached it — so all that is left is to stop the identity provider
     * honoring a grant nobody is holding anymore.
     */
    public function surrender(OauthToken $token): void
    {
        $this->surrenderAll([$token]);
    }

    /**
     * Hand back grants that no row was ever written for.
     *
     * A sign-in exchanges the authorization code before anything can be stored,
     * so a handshake that fails between those two moments is holding a live
     * access token and a live refresh token that nothing will ever point at:
     * there is no row for the account to end and none for `model:prune` to
     * sweep, and they would stay honored at UzAirports ID until they expired on
     * their own. Both places that can be left holding them — the driver, when
     * the profile request fails, and the controller, when the account or the
     * login cannot be written — hand them here.
     *
     * The values go onto an unsaved model because that is what the revocation
     * path reads them off, and the encrypted casts round-trip them unchanged.
     * Nothing is written and nothing is deleted.
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
     * Give several logins' grants up at once, leaving their rows alone.
     *
     * `surrender()` settles its own revocations, so a sweep calling it per row
     * waited out one batch after the next: a command dropping thousands of
     * rows spent a revocation timeout on each of them, in turn, and the sweep
     * took as long as the sum of them all. A whole chunk goes on the wire
     * together here and is waited on once — the same bargain every other bulk
     * path in this package already makes.
     *
     * @param  iterable<array-key, OauthToken>  $tokens
     */
    public function surrenderAll(iterable $tokens): void
    {
        $this->revokeAll($tokens);
    }

    /**
     * Hand every grant back at once and wait for the answers together.
     *
     * Each revocation carries the provider's revocation timeout, and there are
     * up to two per login. Waited on one at a time they add up along both axes:
     * an account on a dozen devices spent up to two dozen timeouts inside the
     * request a browser was holding, and even a single logout paid the access
     * token's wait and the refresh token's wait end to end. None of those calls
     * decides any of the others, so they go on the wire together and the caller
     * waits once — for the slowest, not for the sum.
     *
     * `revocation_concurrency` bounds how many are in flight at a time, so a
     * sweep of an account with an unusual number of logins does not open an
     * unbounded number of sockets at once.
     *
     * A token that will not open is anything this can hand over, and the model
     * has already recorded why — so a login holding only unreadable values is
     * ended locally, and the identity provider is asked for nothing. An account
     * holding no readable grant at all does not even resolve the driver.
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

        // A driver registered under this name that is not this package's is
        // nothing these grants can be handed to. Ending a login is the one
        // thing that must not fail on it: a misconfiguration here would have
        // answered the logout the user asked for with a 500, leaving them
        // looking signed in.
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
     * Put one batch of revocations on the wire and account for what came back.
     *
     * A call that fails before it is even sent is reported where it happens;
     * everything that did go out is settled together, so one refusal neither
     * hides nor cancels the rest.
     *
     * A 401 on an access token is the provider saying it no longer honors what
     * it was being asked to stop honoring, which is the outcome being asked
     * for. It is spared the log; a refresh token refused the same way is not,
     * because that endpoint answers 200 to a token it has already retired.
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

        /** @var array<int, mixed> $results */
        $results = Utils::settle($promises)->wait();

        foreach ($results as $index => $result) {
            if (! is_array($result) || ($result['state'] ?? null) !== PromiseInterface::REJECTED) {
                continue;
            }

            $reason = $result['reason'] ?? null;

            if (! $reason instanceof Throwable || ! isset($sent[$index])) {
                continue;
            }

            $unauthorized = $reason instanceof RequestException && $reason->getResponse()?->getStatusCode() === 401;

            if ($sent[$index]['spareUnauthorized'] && $unauthorized) {
                continue;
            }

            $this->reportFailedRevocation($sent[$index]['token'], $reason);
        }
    }

    /**
     * Start one revocation, reporting a call that could not even be made.
     *
     * Null says there was nothing to send — no endpoint is configured for it,
     * or the attempt failed outright and has been logged.
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
     * A batch of none is not a smaller batch, it is no progress at all, so a
     * misconfigured value falls back to sending them one at a time.
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
            'http_status' => $exception instanceof RequestException ? $exception->getResponse()?->getStatusCode() : null,
        ]);
    }

    /**
     * Drop the named sessions from the session store.
     *
     * @param  array<array-key, string>  $sessionIds
     */
    private function deleteStoredSessionsById(array $sessionIds): void
    {
        if ($sessionIds === [] || config('session.driver') !== 'database') {
            return;
        }

        try {
            $this->storedSessions()->whereIn('id', array_values($sessionIds))->delete();
        } catch (Throwable $e) {
            Log::warning('Failed to delete the stored session of an UzAirports user.', [
                'exception_class' => $e::class,
            ]);
        }
    }

    /**
     * Drop the account's sessions from the session store.
     *
     * The account's own rows and the ones named by the logins being ended are
     * deleted by two statements rather than one. They could be spelled as a
     * single `user_id = ? or id in (…)`, but that reads two different columns
     * in one predicate, and no index answers both halves — so the store falls
     * back to a scan of `sessions`, which in a busy application is among the
     * largest tables there is. Split, each statement enters the index built for
     * the column it names: the primary key for the ids, `user_id` for the rest.
     *
     * Deleting a session is idempotent and the two sets overlap freely, so
     * running them apart matches what the single statement matched. The spared
     * session is taken out of the id list rather than excluded again, since
     * `whereIn` is already naming rows one by one.
     *
     * A store that cannot be reached must not cost the caller the rest of the
     * work, so a failure here is logged: the rows are gone already, and the
     * middleware refuses those sessions on their next request regardless.
     *
     * @param  array<array-key, string>  $sessionIds
     */
    private function deleteStoredSessions(int|string $userId, ?string $exceptSessionId, array $sessionIds = []): void
    {
        if (config('session.driver') !== 'database') {
            return;
        }

        if ($exceptSessionId !== null) {
            $sessionIds = array_filter(
                $sessionIds,
                fn (string $sessionId): bool => $sessionId !== $exceptSessionId
            );
        }

        try {
            $this->storedSessions()
                ->where('user_id', $userId)
                ->when($exceptSessionId !== null, fn ($query) => $query->where('id', '!=', $exceptSessionId))
                ->delete();

            if ($sessionIds !== []) {
                $this->storedSessions()->whereIn('id', array_values($sessionIds))->delete();
            }
        } catch (Throwable $e) {
            Log::warning('Failed to delete the stored sessions of an UzAirports user.', [
                'user_id' => $userId,
                'exception_class' => $e::class,
            ]);
        }
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
