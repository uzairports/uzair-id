<?php

namespace Uzairports\Uzairid\Models;

use Illuminate\Cache\ArrayStore;
use Illuminate\Cache\Repository;
use Illuminate\Contracts\Cache\Repository as CacheRepository;
use Illuminate\Contracts\Debug\ExceptionHandler;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Collection;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Prunable;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Events\ModelsPruned;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Str;
use RuntimeException;
use Throwable;
use Uzairports\Uzairid\Actions\EndSessions;

/**
 * One SSO login: the tokens it was issued and the browser session holding them.
 *
 * A user has one row per session, so the same account may be signed in on a
 * phone and a desktop at once, each with its own grant. That is how OAuth means
 * it: each browser exchanged its own authorization code, so each has its own
 * refresh token to rotate.
 *
 * @property int $id
 * @property int|string $user_id
 * @property string $access_token
 * @property string|null $refresh_token
 * @property Carbon|null $expires_at
 * @property string|null $session_id
 * @property string|null $ip_address
 * @property string|null $user_agent
 * @property Carbon|null $created_at
 * @property Carbon|null $updated_at
 */
class OauthToken extends Model
{
    use Prunable;

    protected $fillable = [
        'access_token',
        'refresh_token',
        'expires_at',
        'session_id',
        'ip_address',
        'user_agent',
    ];

    protected $hidden = [
        'access_token',
        'refresh_token',
        'session_id',
    ];

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'access_token' => 'encrypted',
            'refresh_token' => 'encrypted',
            'expires_at' => 'datetime',
        ];
    }

    /**
     * The access token to this login was issued, or null if it will not open.
     */
    public function readableAccessToken(): ?string
    {
        return $this->readable('access_token');
    }

    /**
     * The refresh token this login was issued, or null if it will not open.
     */
    public function readableRefreshToken(): ?string
    {
        return $this->readable('refresh_token');
    }

    /**
     * Read one of the token columns back, answering null where it will not open.
     *
     * Both columns are `encrypted` casts, so a value written under a key the
     * application no longer holds — a rotated `APP_KEY` with no
     * `APP_PREVIOUS_KEYS` behind it, a dump restored into another environment —
     * raises a decryption failure from wherever the property is read. Left to
     * itself that is a 500 on every request the login touches, including the
     * ones that would have ended it: the grant can neither be spent nor given
     * up, and the account holding it has no way out but a support ticket.
     *
     * Null says the same thing to every caller — there is nothing here that can
     * be spent — so the login is dropped locally, and its owner signs in again,
     * which is what happens to a login whose grant is refused anyway.
     *
     * A column that is merely empty answers null too and says nothing worth
     * recording. The row carrying a value nobody can open is the one worth a
     * line, because it is a key that went missing, not a token that was never
     * issued.
     */
    private function readable(string $attribute): ?string
    {
        try {
            $value = $this->getAttribute($attribute);
        } catch (Throwable $exception) {
            Log::warning('An UzAirports token cannot be read back.', [
                'user_id' => $this->user_id,
                'attribute' => $attribute,
                'exception_class' => $exception::class,
            ]);

            return null;
        }

        return is_string($value) && filled($value) ? $value : null;
    }

    /**
     * @return BelongsTo<Model, $this>
     */
    public function user(): BelongsTo
    {
        $model = config('auth.providers.users.model');

        if (! is_string($model) || ! is_subclass_of($model, Model::class)) {
            throw new RuntimeException('The configured [auth.providers.users.model] is not an Eloquent model.');
        }

        return $this->belongsTo($model);
    }

    /**
     * The logins there is no longer any use for, by the measure each one asks.
     *
     * A row that names a browser session goes by how long it is since anything
     * touched it. A browser that is simply closed leaves its row behind:
     * nothing signs it out, and the session it names expires quietly in the
     * session store. Twice the session lifetime after the row was last used,
     * whatever it names is gone, and so is any use for the row.
     *
     * What makes that safe is `keepAlive()`: the row is written again while its
     * browser is still making requests, so `updated_at` means "last seen" and
     * not merely "last refreshed". Without it a login whose access token
     * outlives the window — an identity provider handing out an eight-hour
     * token against a two-hour session lifetime — would go untouched while its
     * owner worked and be pruned out from under them.
     *
     * A row carrying no `updated_at` is swept on sight. `timestamps()` leaves
     * the column nullable, so a row written around Eloquent — a seeder, a data
     * migration, an import — can arrive without one, and null answers no
     * comparison: matched by `<` alone such a row is not merely kept, it is
     * kept for good, because nothing but `keepAlive()` on a request it may
     * never see would ever give it a date to be measured by.
     *
     * A row that names no session is measured by nothing of the sort, and used
     * to be. `session_id` is nullable so that a login can be held outside a
     * browser — an API client, a console command — and the whole argument above
     * rests on a session having quietly expired somewhere. There is none. Such
     * a login was being collected after four hours of an idle API on the
     * default settings, and its grant handed back with it, which is a
     * credential deleted for the crime of not being called overnight.
     *
     * It is measured by whether anything can still be done with it instead: a
     * login holding no refresh token, whose access token has run out, cannot be
     * spent and cannot be renewed. That is the whole of it — while a refresh
     * token is there, the login renews indefinitely and is nobody's to collect
     * on a timer. Those are ended deliberately, through `uzair.logoutDevice` or
     * `EndSessions`, the way a credential is.
     *
     * The two are one bracketed group, not two clauses side by side. Callers
     * narrow this query further — `deleteForPruning()` adds `whereKey()` — and
     * `A OR B AND key = ?` is not what any of them mean.
     *
     * Pruning runs through Laravel's `model:prune` command, which the host
     * application has to schedule for the rows to actually go.
     *
     * @return Builder<OauthToken>
     */
    public function prunable(): Builder
    {
        $abandoned = now()->subMinutes(self::sessionLifetime() * 2);

        return $this->newQuery()->where(
            fn (Builder $query) => $query
                ->where(
                    fn (Builder $browser) => $browser
                        ->whereNotNull('session_id')
                        ->where(
                            fn (Builder $unseen) => $unseen
                                ->where('updated_at', '<', $abandoned)
                                ->orWhereNull('updated_at')
                        )
                )
                ->orWhere(
                    fn (Builder $issued) => $issued
                        ->whereNull('session_id')
                        ->whereNull('refresh_token')
                        ->where(
                            fn (Builder $spent) => $spent
                                ->whereNull('expires_at')
                                ->orWhere('expires_at', '<', now())
                        )
                )
        );
    }

    protected static ?EndSessions $pruner = null;

    /**
     * Flush the cached pruner instance between sweeps, requests, or tests.
     *
     * Reached on every Octane request through `Uzair::flushState()`, so a
     * worker never hands the next request an action built out of a container
     * the application has since rebound.
     */
    public static function flushPruner(): void
    {
        static::$pruner = null;
    }

    /**
     * Sweep the abandoned logins, handing a chunk's grants back together.
     *
     * The trait's own sweep prunes one model at a time, and `pruning()` settles
     * that row's revocations before the next one is even read. Every row
     * therefore cost its own wait on the identity provider — up to the
     * revocation timeout apiece — so a command dropping thousands of them took
     * as long as the sum of them all, which for a real backlog is hours rather
     * than minutes. `revoke_on_prune` was the only way out, and turning it off
     * means leaving live grants behind.
     *
     * A chunk's grants go out together instead and are waited on once, which is
     * how every other bulk path in this package already spends them. The rows
     * are still deleted one apiece, the way the trait deletes them, so anything
     * observing the model hears about each of them; `pruning()` is not called
     * along the way. The rows are rechecked and deleted under a row lock,
     * then their grants are surrendered after the transactions have committed.
     *
     * A row that will not delete is reported, and the sweep carries on again as
     * the trait does: one unhappy row must not leave the rest of the backlog
     * standing.
     *
     * @throws Throwable
     */
    public function pruneAll(int $chunkSize = 1000): int
    {
        $total = 0;

        $this->prunable()->chunkById($chunkSize, function (Collection $tokens) use (&$total): void {
            $total += $this->pruneChunk($tokens);

            Event::dispatch(new ModelsPruned(static::class, $total));
        });

        return $total;
    }

    /**
     * Delete still-abandoned logins before surrendering their current grants.
     *
     * The entries the resolved logins were cached undergo too. Pruning is the
     * one path that used to leave them — `login_cache_ttl` documents a swept
     * row as exactly what the entry's lifetime covers — but the sweep is
     * holding every session id it is about to orphan anyway, and dropping them
     * costs one call for the whole chunk.
     *
     * @param  Collection<int, OauthToken>  $tokens
     * @return int the number of rows actually dropped
     *
     * @throws Throwable
     */
    private function pruneChunk(Collection $tokens): int
    {
        if ($tokens->isEmpty()) {
            return 0;
        }

        /** @var list<OauthToken> $pruned */
        $pruned = [];

        /** @var array<string, true> $sessionIds */
        $sessionIds = [];

        try {
            foreach ($tokens as $token) {
                try {
                    if (! $token->deleteForPruning(onlyAbandoned: true)) {
                        continue;
                    }
                } catch (Throwable $exception) {
                    app(ExceptionHandler::class)->report($exception);

                    continue;
                }

                $pruned[] = $token;

                $sessionId = $token->session_id;

                if (is_string($sessionId) && $sessionId !== '') {
                    $sessionIds[$sessionId] = true;
                }
            }
        } finally {
            try {
                static::forgetLogins(array_keys($sessionIds));
            } finally {
                if ($pruned !== [] && config('uzairports.revoke_on_prune', true)) {
                    (static::$pruner ??= app(EndSessions::class))->surrenderAll($pruned);
                }
            }
        }

        return count($pruned);
    }

    /**
     * Prune one explicitly selected login and surrender its current grants.
     *
     * Like the trait's single prune(), this does not apply the sweep's age
     * filter. The pruning hook runs before deletion, but remote revocation
     * runs after commit, so a concurrent refresh cannot leave new grants behind.
     */
    public function prune(): bool
    {
        if (! $this->deleteForPruning(onlyAbandoned: false)) {
            return false;
        }

        try {
            static::forgetLogin($this->session_id);
        } finally {
            if (config('uzairports.revoke_on_prune', true)) {
                (static::$pruner ??= app(EndSessions::class))->surrender($this);
            }
        }

        return true;
    }

    /**
     * Re-read and delete under the same row lock used to persist a refresh.
     */
    private function deleteForPruning(bool $onlyAbandoned): bool
    {
        return $this->getConnection()->transaction(function () use ($onlyAbandoned): bool {
            $query = $onlyAbandoned ? $this->prunable() : $this->newQuery();
            $stored = $query->whereKey($this->getKey())->lockForUpdate()->first();

            if ($stored === null) {
                return false;
            }

            $this->setRawAttributes($stored->getAttributes(), sync: true);

            if (! $onlyAbandoned) {
                $this->pruning();
            }

            return $this->delete() === true;
        });
    }

    /**
     * Record that the login is still in use, if it has not been written lately.
     *
     * `updated_at` is what pruning reads, and nothing else writes the row
     * between refreshes — so on its own it would say when the token last
     * changed rather than when the browser was last here. This closes that gap
     * while keeping the cost to one writing per half a session lifetime, instead
     * of one on every request.
     *
     * The column is nullable, and a row written around Eloquent — a raw insert,
     * an import from an earlier version of the package — arrives with nothing
     * in it. Such a row is not merely unreadable here: `prunable()` compares
     * against `updated_at`, and null answers no comparison, so it would never
     * be collected either. It is stamped as seen now, which both answers the
     * question and puts the row back in reach of pruning.
     */
    public function keepAlive(): void
    {
        $staleAfter = now()->subMinutes(max(intdiv(self::sessionLifetime(), 2), 1));

        if ($this->updated_at !== null && $this->updated_at->greaterThan($staleAfter)) {
            return;
        }

        $this->forceFill(['updated_at' => now()])->saveQuietly();
    }

    /**
     * How long the host application keeps a session, in minutes.
     *
     * A lifetime that is not a number is a misconfiguration, and casting one
     * would read as zero — pruning every login on the next sweep. The default
     * stands instead.
     */
    private static function sessionLifetime(): int
    {
        $lifetime = config('session.lifetime', 120);

        return max(is_numeric($lifetime) ? (int) $lifetime : 120, 1);
    }

    /**
     * How long a resolved login may answer for the row, in seconds.
     *
     * Zero — the default — means it may not, and every request reads the row.
     */
    public static function loginCacheTtl(): int
    {
        $ttl = config('uzairports.login_cache_ttl', 0);

        return max(is_numeric($ttl) ? (int) $ttl : 0, 0);
    }

    /**
     * The store the resolved logins are kept in.
     *
     * `login_cache_store` is null by default, so whatever the application
     * caches in is what an ended login has to be forgotten from. That is good
     * enough only while every process serving the application reads the same
     * store: `forgetLogin()` cannot reach across two that do not share, so a
     * device signed out through one of them keeps being let through by the rest
     * until the entry lapses. The setting exists so the entries can be pointed
     * at a shared store without moving what the application caches in.
     *
     * A store held in the memory of one process is the case that can be seen
     * from here, and it is worth saying: nothing it writes is ever read back,
     * so the lifetime buys none of the reads it was set for, and nothing it
     * forgets is forgotten anywhere else. Nothing is refused over it — an entry
     * nobody can find behaves exactly like the default of reading the row — and
     * it is said once per process, because this sits on the hot path.
     *
     * A store that is shared but not in memory — Redis, Memcached, the database
     * — cannot be told apart from one that is not by looking at it, so `file`
     * across several servers is left to the operator and to the note on
     * `login_cache_store` in the published configuration.
     */
    private static function loginCache(): CacheRepository
    {
        $configured = config('uzairports.login_cache_store');

        $repository = is_string($configured) && $configured !== ''
            ? Cache::store($configured)
            : Cache::store();

        // What the entries live in is the store, not the repository wrapping
        // it, and only a repository can be asked for one.
        $store = $repository instanceof Repository ? $repository->getStore() : null;

        if ($store instanceof ArrayStore) {
            self::warnAboutTheLoginCache(
                'The cache store behind [uzairports.login_cache_store] lives in the memory of one process, so a resolved UzAirports login is never read back by another process and a login ended in one keeps being let through by the rest until its entry lapses. Point it at a store every process shares.'
            );
        }

        return $repository;
    }

    /**
     * What has already been said about the login cache in this process.
     *
     * @var array<string, true>
     */
    private static array $reportedAboutTheLoginCache = [];

    /**
     * Let the warnings be said again, for a suite that asserts on them.
     *
     * Reached between requests on a long-lived runtime through
     * `Uzair::flushState()`, which is where the reason is written down.
     */
    public static function flushLoginCacheWarnings(): void
    {
        self::$reportedAboutTheLoginCache = [];
    }

    /**
     * Say a thing about the login cache once, however many requests notice it.
     *
     * This is read on every request the middleware lets through, and a
     * misconfigured store stays misconfigured — so the line is worth writing
     * once and worth nothing repeated on every request that finds it.
     */
    private static function warnAboutTheLoginCache(string $message): void
    {
        if (isset(self::$reportedAboutTheLoginCache[$message])) {
            return;
        }

        self::$reportedAboutTheLoginCache[$message] = true;

        Log::warning($message);
    }

    /**
     * What was last resolved for a session if it may still be used.
     *
     * The account is carried alongside the expiry because a session id is not
     * proof of whose login it names: an entry left by whoever held the session
     * before must not answer for whoever holds it now, and the caller compares
     * the two before trusting it.
     *
     * A store that will not answer has anything to say about the login, so the
     * row is read instead — which is what `login_cache_ttl` being zero does on
     * every request anyway. Left to itself, the failure came out of the
     * middleware, and a cache outage answered every authenticated request with
     * a 500: an optimization nobody asked for taking the application down.
     *
     * @return array{user: string, expires_at: int|null}|null
     */
    public static function cachedLogin(string $sessionId): ?array
    {
        if (self::loginCacheTtl() === 0) {
            return null;
        }

        try {
            $cached = self::loginCache()->get(self::loginCacheKey($sessionId));
        } catch (Throwable $exception) {
            self::reportLoginCacheFailure('answer for a resolved UzAirports login, so the row is read instead', $exception);

            return null;
        }

        if (! is_array($cached) || ! is_string($cached['user'] ?? null)) {
            return null;
        }

        $expiresAt = $cached['expires_at'] ?? null;

        return [
            'user' => $cached['user'],
            'expires_at' => is_int($expiresAt) ? $expiresAt : null,
        ];
    }

    /**
     * Let this login answer for its row until the entry lapses.
     *
     * An entry that cannot be written is an entry the next request will not
     * find, and a request that finds none reads the row — so a store that will
     * not take it costs a query and nothing else. Raised through, it answered a
     * request whose login had just been resolved as perfectly fresh with a 500.
     *
     * Only the writing is caught. The read around it is this application's own
     * database, and a failure there is not something to swallow on the way to
     * an optimization.
     *
     * @throws Throwable
     */
    public function cacheLogin(string $sessionId): void
    {
        $ttl = self::loginCacheTtl();

        if ($ttl === 0 || $sessionId === '') {
            return;
        }

        // Hold the row until publication finishes, so deletion cannot forget
        // the entry between checking the login and writing its cached answer.
        //
        // Shared rather than exclusive. All this needs is that a deleted cannot
        // commit in between, and a shared lock blocks one — it wants the row
        // exclusively. What it does not block is another request of the same
        // account publishing at the same moment, which is the common case and
        // used to queue: the entry is written under this lock, so an exclusive
        // one held the row for the length of a call to the cache store, and a
        // store having a slow minute became lock waits on the login itself.
        // Nothing here writes the row, so there is no upgrade to deadlock over.
        $this->getConnection()->transaction(function () use ($sessionId, $ttl): void {
            $stored = $this->newQuery()
                ->whereKey($this->getKey())
                ->where('session_id', $sessionId)
                ->sharedLock()
                ->first(['id', 'user_id', 'expires_at']);

            if ($stored === null) {
                return;
            }

            try {
                self::loginCache()->put(self::loginCacheKey($sessionId), [
                    'user' => (string) $stored->user_id,
                    'expires_at' => $stored->expires_at?->getTimestamp(),
                ], $ttl);
            } catch (Throwable $exception) {
                self::reportLoginCacheFailure('hold a resolved UzAirports login, so the next request reads the row instead', $exception);
            }
        });
    }

    /**
     * Stop a session's entry answering for a row that is no longer there.
     *
     * Every path in the package that ends a login calls this, so a device
     * signed out from another one stops being let through as soon as that
     * request finishes rather than when the entry lapses — as long as the two
     * share a cache store, which any deployment running more than one process
     * already needs for locks.
     *
     * A row dropped from outside the package — a sweep, a handwritten delete —
     * is what the entry's lifetime is actually covering.
     *
     * A store that will not drop the entry is reported and not raised through,
     * for the reason `forgetLogins()` gives at length: every caller here has
     * already deleted the row, and the ending must finish.
     */
    public static function forgetLogin(?string $sessionId): void
    {
        if ($sessionId === null || $sessionId === '' || self::loginCacheTtl() === 0) {
            return;
        }

        try {
            self::loginCache()->forget(self::loginCacheKey($sessionId));
        } catch (Throwable $exception) {
            self::reportLoginCacheFailure('drop a resolved UzAirports login, so that device may be let through until the entry lapses', $exception);
        }
    }

    /**
     * Stop several sessions' entries answering for rows that are no longer there.
     *
     * Ending an account's logins forgets one entry per login, and this is the
     * one call the callers make for all of them. What it is not is one command
     * on the wire: `Illuminate\Cache\Repository::deleteMultiple()` loops
     * `forget()` over the keys, and no first-party store overrides it, so a
     * remote store is still charged a round-trip apiece. The comment that used
     * to stand here promised the round-trips were saved and they never were.
     *
     * Whether that is worth going under the repository for depends on the
     * caller: a logout drops one entry, `single_session` a handful, and only a
     * pruning sweep of an unusual backlog drops enough for the difference to be
     * measurable. Nothing here is on a browser's critical path in a quantity
     * that shows, so it stays on the contract every store implements.
     *
     * A store that will not answer is reported and not raised through. Every
     * caller has already deleted the rows by the time this runs, and the rest
     * of the ending — dropping the sessions, handing the grants back to the
     * identity provider — must not be skipped over a cache: the row is gone, so
     * the middleware refuses that device the moment the entry lapses, and the
     * `login_cache_ttl` note is where the seconds in between are documented.
     *
     * @param  array<array-key, string>  $sessionIds
     */
    public static function forgetLogins(array $sessionIds): void
    {
        if (self::loginCacheTtl() === 0) {
            return;
        }

        $keys = [];

        foreach ($sessionIds as $sessionId) {
            if ($sessionId !== '') {
                $keys[] = self::loginCacheKey($sessionId);
            }
        }

        if ($keys === []) {
            return;
        }

        try {
            self::loginCache()->deleteMultiple($keys);
        } catch (Throwable $exception) {
            self::reportLoginCacheFailure('drop the resolved UzAirports logins of ended sessions, so those devices may be let through until their entries lapse', $exception);
        }
    }

    /**
     * Say that the login cache would not answer, once per process.
     *
     * A store that is down for every request, and the line is worth
     * writing once and worth nothing repeated on each of them — the same
     * bargain `warnAboutTheLoginCache()` already makes for a misconfigured
     * store, and the same one `flushLoginCacheWarnings()` undoes for a test.
     */
    private static function reportLoginCacheFailure(string $refusedTo, Throwable $exception): void
    {
        self::warnAboutTheLoginCache(
            "The cache store behind [uzairports.login_cache_store] would not {$refusedTo}. (".$exception::class.')'
        );
    }

    /**
     * The entry of a session's login is kept under.
     *
     * The session id is hashed rather than spelled out: it is the credential
     * the browser holds, and a cache store is a place where keys are routinely listed
     * and dumped.
     */
    private static function loginCacheKey(string $sessionId): string
    {
        return 'uzairid:login:'.hash('sha256', $sessionId);
    }

    /**
     * Determine whether the access token has already expired.
     *
     * Tokens stored without expiry are treated as expired so that they are
     * refreshed once and gain a known lifetime.
     */
    public function hasExpired(): bool
    {
        return $this->expiresWithin(0);
    }

    /**
     * Determine whether the access token expires within the given number of seconds.
     */
    public function expiresWithin(int $seconds): bool
    {
        if ($this->expires_at === null) {
            return true;
        }

        return $this->expires_at->lessThanOrEqualTo(now()->addSeconds($seconds));
    }

    /**
     * A short name for the device this login is running on.
     *
     * It is a guess read off the user agent, which is a string the browser is
     * free to make up: good enough for a person to recognize their own phone in
     * a list, never good enough to decide anything on.
     */
    public function deviceLabel(): string
    {
        $agent = (string) $this->user_agent;

        if ($agent === '') {
            return __('uzairid::messages.unknown_device');
        }

        $browsers = [
            'Vivaldi' => 'Vivaldi',
            'Brave' => 'Brave',
            'Edg' => 'Edge',
            'OPR' => 'Opera',
            'YaBrowser' => 'Yandex',
            'SamsungBrowser' => 'Samsung Internet',
            'DuckDuckGo' => 'DuckDuckGo',
            'MiuiBrowser' => 'Miui Browser',
            'UCBrowser' => 'UC Browser',
            '; wv' => 'WebView',
            'WebView' => 'WebView',
            'Firefox' => 'Firefox',
            'Chrome' => 'Chrome',
            'Safari' => 'Safari',
        ];
        $platforms = [
            'Android' => 'Android',
            'iPhone' => 'iPhone',
            'iPad' => 'iPad',
            'Windows' => 'Windows',
            'Macintosh' => 'macOS',
            'CrOS' => 'ChromeOS',
            'Linux' => 'Linux',
        ];

        $browser = $this->firstMatch($agent, $browsers);
        $platform = $this->firstMatch($agent, $platforms);

        if ($browser === null && $platform === null) {
            return Str::limit($agent, 40);
        }

        return trim(($browser ?? '').' — '.($platform ?? ''), ' —');
    }

    /**
     * @param  array<string, string>  $needles
     */
    private function firstMatch(string $agent, array $needles): ?string
    {
        foreach ($needles as $needle => $label) {
            if (str_contains($agent, $needle)) {
                return $label;
            }
        }

        return null;
    }
}
