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
use Illuminate\Database\UniqueConstraintViolationException;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Str;
use Throwable;
use Uzairports\Uzairid\Actions\EndSessions;
use Uzairports\Uzairid\Uzair;

/**
 * One SSO login: the tokens it was issued and the session or client holding them.
 *
 * A user has one row per browser session or mobile client, each with its own
 * grant and refresh token to rotate.
 *
 * @property int $id
 * @property int|string $user_id
 * @property string $access_token
 * @property string|null $refresh_token
 * @property Carbon|null $expires_at
 * @property string|null $session_id
 * @property int|string|null $personal_access_token_id
 * @property string|null $ip_address
 * @property string|null $user_agent
 * @property string|null $sid
 * @property string|null $id_token
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
        'sid',
        'id_token',
    ];

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'access_token' => 'encrypted',
            'refresh_token' => 'encrypted',
            'id_token' => 'encrypted',
            'expires_at' => 'datetime',
        ];
    }

    /**
     * The ID token this login was issued, or null without one or if it cannot
     * be decrypted. Only ever handed back to the provider as `id_token_hint`.
     */
    public function readableIdToken(): ?string
    {
        return $this->readable('id_token');
    }

    /**
     * The access token of this login, or null if it cannot be decrypted.
     */
    public function readableAccessToken(): ?string
    {
        return $this->readable('access_token');
    }

    /**
     * The refresh token of this login, or null if it cannot be decrypted.
     */
    public function readableRefreshToken(): ?string
    {
        return $this->readable('refresh_token');
    }

    /**
     * Read an encrypted token column, answering null when it cannot be decrypted.
     *
     * A value written under a key the application no longer holds (a rotated
     * `APP_KEY`, a restored dump) must not raise, or every request touching the
     * login fails, including the ones that would end it. Null means "nothing to
     * spend", so the login is dropped and its owner signs in again. Only an
     * undecryptable value is logged; an empty column is not.
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
     * Narrow a query to the login held by one caller, checked in this order:
     *
     * - a mobile client, by its Sanctum token (first, because a token may reach
     *   a route that also starts a session the login was not filed under);
     * - a browser, by its session;
     * - anything else, only against logins naming neither, so it never borrows
     *   a phone's grant; the most recent such row is taken.
     *
     * @param  Builder<OauthToken>  $query
     */
    public function scopeHeldBy(Builder $query, ?string $sessionId, int|string|null $accessTokenId = null): void
    {
        if ($accessTokenId !== null) {
            $query->where('personal_access_token_id', $accessTokenId);

            return;
        }

        if ($sessionId !== null) {
            $query->where('session_id', $sessionId);

            return;
        }

        $query->whereNull('session_id')->whereNull('personal_access_token_id')->latest('id');
    }

    /**
     * @return BelongsTo<Model, $this>
     */
    public function user(): BelongsTo
    {
        $model = Uzair::userModel();

        return $this->belongsTo($model, 'user_id');
    }

    /**
     * The logins there is no longer any use for.
     *
     * - A browser login goes once `updated_at` is older than twice the session
     *   lifetime, or null (a row written around Eloquent would otherwise never
     *   match). `keepAlive()` keeps `updated_at` meaning "last seen".
     * - A sessionless login goes only when it can no longer be spent or renewed:
     *   no refresh token and an expired or unknown access token. One holding a
     *   refresh token is ended deliberately, never on a timer.
     * - A mobile login goes once its Sanctum token is gone. The subquery assumes
     *   both tables live on the same connection.
     *
     * The measures form one bracketed group because callers narrow the query
     * further (`deleteForPruning()` adds `whereKey()`); do not flatten it. Rows
     * go only when the host application schedules `model:prune`.
     *
     * The projection is covariant so it holds whether larastan infers
     * `Builder<OauthToken>` or `Builder<static>` for `newQuery()`.
     *
     * @return Builder<covariant OauthToken>
     */
    public function prunable(): Builder
    {
        $abandoned = now()->subMinutes(self::sessionLifetime() * 2);
        $accessTokenModel = Uzair::accessTokenModel();
        $accessToken = $accessTokenModel !== null ? new $accessTokenModel : null;

        if ($accessToken !== null && ! self::accessTokensTableExists($accessToken)) {
            $accessToken = null;
        }

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
                ->when($accessToken, fn (Builder $query, Model $accessToken) => $query->orWhere(
                    fn (Builder $orphaned) => $this->withoutItsAccessToken($orphaned, $accessToken)
                ))
        );
    }

    /**
     * Narrow to the logins whose Sanctum token is no longer there.
     *
     * @param  Builder<covariant OauthToken>  $query
     */
    private function withoutItsAccessToken(Builder $query, Model $accessToken): void
    {
        $query
            ->whereNotNull('personal_access_token_id')
            ->whereNotExists(
                fn ($tokens) => $tokens
                    ->from($accessToken->getTable())
                    ->whereColumn($accessToken->getQualifiedKeyName(), $this->qualifyColumn('personal_access_token_id'))
            );
    }

    protected static ?EndSessions $pruner = null;

    /**
     * Flush the cached pruner instance between sweeps, requests, or tests.
     *
     * Called through `Uzair::flushState()` so a long-lived worker never reuses
     * an action built from a container that has since been rebound.
     */
    public static function flushPruner(): void
    {
        static::$pruner = null;
    }

    /**
     * Sanctum token tables found to exist in this process, by connection and table.
     *
     * @var array<string, true>
     */
    private static array $accessTokensTables = [];

    /**
     * Whether Sanctum's token table exists, so pruning can ask about it.
     *
     * Sanctum may be installed for an SPA's cookie authentication alone, with
     * its token table never migrated; pruning must not fail on that. Only a
     * table found is remembered, since `prunable()` runs once per pruned row.
     */
    private static function accessTokensTableExists(Model $accessToken): bool
    {
        $key = $accessToken->getConnection()->getName().'|'.$accessToken->getTable();

        if (isset(self::$accessTokensTables[$key])) {
            return true;
        }

        if (! $accessToken->getConnection()->getSchemaBuilder()->hasTable($accessToken->getTable())) {
            return false;
        }

        return self::$accessTokensTables[$key] = true;
    }

    /**
     * Forget the Sanctum token tables found, between requests or tests.
     */
    public static function flushAccessTokensTables(): void
    {
        self::$accessTokensTables = [];
    }

    /**
     * Sweep the abandoned logins, revoking each chunk's grants in one batch.
     *
     * Overrides the trait so revocations are awaited once per chunk rather than
     * once per row. Rows are still rechecked and deleted one apiece under a row
     * lock, so model events fire; `pruning()` is not called, or grants would be
     * revoked twice. Grants are surrendered after commit. A row that fails to
     * delete is reported and the sweep continues.
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
     * Delete still-abandoned logins, then forget their cached logins and
     * surrender only the grants of rows that actually deleted.
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

        /** @var list<int|string> $accessTokenIds */
        $accessTokenIds = [];

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

                if ($token->personal_access_token_id !== null) {
                    $accessTokenIds[] = $token->personal_access_token_id;
                }
            }
        } finally {
            try {
                static::forgetLogins(array_keys($sessionIds));
                (static::$pruner ??= app(EndSessions::class))->dropAccessTokens($accessTokenIds);
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
     * Skips the sweep's age filter. The pruning hook runs before deletion and
     * revocation after commit, so a concurrent refresh cannot leave new grants
     * behind.
     */
    public function prune(): bool
    {
        if (! $this->deleteForPruning(onlyAbandoned: false)) {
            return false;
        }

        try {
            static::forgetLogin($this->session_id);

            if ($this->personal_access_token_id !== null) {
                (static::$pruner ??= app(EndSessions::class))->dropAccessTokens([$this->personal_access_token_id]);
            }
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
     * Pruning reads `updated_at` as "last seen", so it is touched at most once
     * per half session lifetime rather than on every request. A null
     * `updated_at` is stamped now.
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
     * File an account's login under the session id its browser now carries,
     * after `session()->regenerate()` changed it.
     *
     * Scoped to the account, because a session id does not prove ownership;
     * `Uzair::followRegeneratedSession()` checks the session payload first.
     * Written without model events: only the filing changed, not the grants.
     * Nothing moved is not proof there is nothing to find: a concurrent request
     * of the same browser may have moved the row a moment earlier. The caller
     * looks again either way; the note it keeps means this happens once per
     * regeneration. A unique-constraint collision is the same race.
     *
     * @return bool whether the login is worth looking for under the new id
     */
    public static function followSession(int|string $userId, string $previousSessionId, string $sessionId): bool
    {
        if ($previousSessionId === '' || $sessionId === '' || $previousSessionId === $sessionId) {
            return false;
        }

        try {
            $moved = static::query()
                ->where('user_id', $userId)
                ->where('session_id', $previousSessionId)
                ->update(['session_id' => $sessionId]);
        } catch (UniqueConstraintViolationException) {
            return true;
        }

        if ($moved === 0) {
            return true;
        }

        // Every session id this package stops using has its cache entry dropped.
        self::forgetLogin($previousSessionId);

        return true;
    }

    /**
     * How long the host application keeps a session, in minutes.
     *
     * A non-numeric value falls back to the default rather than casting to
     * zero, which would prune every login.
     */
    private static function sessionLifetime(): int
    {
        $lifetime = config('session.lifetime', 120);

        return max(is_numeric($lifetime) ? (int) $lifetime : 120, 1);
    }

    /**
     * How long a resolved login may stand in for the row, in seconds; zero
     * (the default) disables the cache.
     */
    public static function loginCacheTtl(): int
    {
        $ttl = config('uzairports.login_cache_ttl', 0);

        return max(is_numeric($ttl) ? (int) $ttl : 0, 0);
    }

    /**
     * The store the resolved logins are kept in.
     *
     * `login_cache_store` (null = the default store) must be shared by every
     * process, or `forgetLogin()` cannot reach them all. An in-process
     * `ArrayStore` is warned about once per process but not refused; other
     * unshared stores (e.g. `file` across servers) cannot be detected here.
     */
    private static function loginCache(): CacheRepository
    {
        $configured = config('uzairports.login_cache_store');

        $repository = is_string($configured) && $configured !== ''
            ? Cache::store($configured)
            : Cache::store();

        // Only a concrete repository exposes its underlying store.
        $store = $repository instanceof Repository ? $repository->getStore() : null;

        if ($store instanceof ArrayStore) {
            self::warnAboutTheLoginCache(
                'The cache store behind [uzairports.login_cache_store] lives in the memory of one process, so a resolved UzAirports login is never read back by another process and a login ended in one keeps being let through by the rest until its entry lapses. Point it at a store every process shares.'
            );
        }

        return $repository;
    }

    /**
     * Login cache warnings already logged in this process.
     *
     * @var array<string, true>
     */
    private static array $reportedAboutTheLoginCache = [];

    /**
     * Let the warnings be logged again; called through `Uzair::flushState()`.
     */
    public static function flushLoginCacheWarnings(): void
    {
        self::$reportedAboutTheLoginCache = [];
    }

    /**
     * Log a login cache warning once per process, since this is on the hot path.
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
     * What was last resolved for a session, if it may still be used.
     *
     * The account is stored with the expiry because a session id does not prove
     * ownership; the caller compares it before trusting the entry. A failing
     * store is reported and answers null, so the row is read instead.
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
     * Let this login stand in for its row until the entry lapses.
     *
     * A failing cache write is reported, not raised: the next request just reads
     * the row. Only the cache call is caught; database failures still raise.
     *
     * @throws Throwable
     */
    public function cacheLogin(string $sessionId): void
    {
        $ttl = self::loginCacheTtl();

        if ($ttl === 0 || $sessionId === '') {
            return;
        }

        // Hold the row until publication finishes, so a deletion cannot forget
        // the entry between checking the login and writing its cached answer.
        // The lock is shared: it blocks a delete but lets concurrent requests of
        // the same login publish in parallel. Nothing here writes the row, so
        // there is no lock upgrade to deadlock over.
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
     * Stop a session's entry standing in for a row that is no longer there.
     *
     * Every path that ends a login must call this. A failing store is reported,
     * not raised, because the row is already deleted and the ending must finish.
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
     * Stop several sessions' entries standing in for rows that are no longer there.
     *
     * `deleteMultiple()` still costs one round-trip per key on first-party
     * stores. A failing store is reported, not raised, so the rest of the
     * ending (sessions, revocation) is never skipped.
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
     * Report that the login cache failed, once per process.
     */
    private static function reportLoginCacheFailure(string $refusedTo, Throwable $exception): void
    {
        self::warnAboutTheLoginCache(
            "The cache store behind [uzairports.login_cache_store] would not {$refusedTo}. (".$exception::class.')'
        );
    }

    /**
     * The cache key for a session's login.
     *
     * The session id is hashed because it is a credential and cache keys are
     * routinely listed.
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
     * A guess from the user agent, for display only; never decide anything on it.
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
