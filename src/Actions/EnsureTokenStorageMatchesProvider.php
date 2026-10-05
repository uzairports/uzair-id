<?php

namespace Uzairports\Uzairid\Actions;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\QueryException;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Log;
use RuntimeException;
use Symfony\Component\HttpKernel\Exception\ServiceUnavailableHttpException;
use Throwable;
use Uzairports\Uzairid\Models\OauthToken;
use Uzairports\Uzairid\Uzair;

class EnsureTokenStorageMatchesProvider
{
    /**
     * When each storage this process verified stops being trusted, by fingerprint.
     *
     * @var array<string, int>
     */
    private static array $verifiedUntil = [];

    public function forUser(Authenticatable $user): void
    {
        $this();

        if (! Uzair::accountMatchesProvider($user)) {
            throw new ServiceUnavailableHttpException(null, 'The route account does not belong to the UzAirports provider.');
        }
    }

    /**
     * Refuse to go on while the token table does not fit the account provider.
     *
     * The check reads the schema — three introspection queries — and runs on
     * every request through `uzair.token`, so a storage found correct is
     * trusted for `storage_check_ttl` seconds: in this process, and in the
     * cache so that the next PHP-FPM request is spared too. The entry is keyed
     * by what the answer depends on — the connection, the token table and the
     * account model — so changing the provider is checked at once. A problem
     * is never remembered: fixing it takes effect on the next request.
     *
     * `uzair:provider --rebuild-empty` forgets the answer when it replaces
     * the table.
     */
    public function __invoke(): void
    {
        try {
            $fingerprint = $this->fingerprint();
        } catch (RuntimeException $exception) {
            $this->refuse($exception->getMessage());
        }

        if ($this->isVerified($fingerprint)) {
            return;
        }

        try {
            $problem = $this->problem();
        } catch (QueryException $exception) {
            // A database failure is not a configuration problem, and its message
            // names hosts, users and SQL: it is logged, never sent to the client.
            Log::error('The UzAirports token storage could not be checked.', [
                'exception_class' => $exception::class,
                'message' => $exception->getMessage(),
            ]);

            throw new ServiceUnavailableHttpException(null, 'The UzAirports token storage could not be checked.');
        } catch (RuntimeException $exception) {
            $problem = $exception->getMessage();
        }

        if ($problem !== null) {
            $this->refuse($problem);
        }

        $this->rememberVerified($fingerprint);
    }

    /**
     * Stop trusting the verified storage, in this process and in the cache.
     */
    public function forgetVerified(): void
    {
        self::$verifiedUntil = [];

        try {
            Cache::store()->forget($this->cacheKey($this->fingerprint()));
        } catch (Throwable) {
            // An entry that cannot be dropped lapses on its own.
        }
    }

    /**
     * Forget what this process verified, for a suite that changes the schema.
     */
    public static function flushVerified(): void
    {
        self::$verifiedUntil = [];
    }

    /**
     * The existing foreign key is the evidence of which accounts own these ids.
     * Never reinterpret existing rows after a guard or model configuration change.
     */
    public function problem(): ?string
    {
        $model = Uzair::userModel();
        $user = new $model;
        $token = new OauthToken;
        $connection = $token->getConnection();
        $schema = $connection->getSchemaBuilder();

        if ($user->getConnection()->getName() !== $connection->getName()) {
            return 'The UzAirports account and token models must use the same database connection.';
        }

        if (! $schema->hasTable($token->getTable())) {
            return 'The UzAirports token table is missing. Publish and run the package migrations.';
        }

        // Every lookup names this column, so a table predating it would answer
        // the first request with a database error instead of this line.
        if (! $schema->hasColumn($token->getTable(), 'personal_access_token_id')) {
            return 'The UzAirports token table predates personal_access_token_id. Run php artisan vendor:publish --tag=uzairid-upgrade-migrations and php artisan migrate.';
        }

        [$expectedSchema, $expectedTable] = $schema->parseSchemaAndTable($user->getTable(), withDefaultSchema: true);
        $expected = $connection->getTablePrefix().$expectedTable;

        foreach ($schema->getForeignKeys($token->getTable()) as $key) {
            if ($key['columns'] !== ['user_id']) {
                continue;
            }

            if ($key['foreign_schema'] === $expectedSchema && $key['foreign_table'] === $expected
                && $key['foreign_columns'] === [$user->getKeyName()]) {
                return null;
            }

            return "The UzAirports token owner is [{$key['foreign_table']}], but the configured provider uses [{$expected}]. Run php artisan uzair:provider for the transition procedure.";
        }

        return 'The UzAirports token owner cannot be verified without a user_id foreign key. Run php artisan uzair:provider.';
    }

    /**
     * @throws ServiceUnavailableHttpException always
     */
    private function refuse(string $problem): never
    {
        Log::error($problem);

        throw new ServiceUnavailableHttpException(null, $problem);
    }

    /**
     * What the answer of `problem()` depends on, read without a query.
     *
     * The database name and the table prefix are part of it: a multi-tenant
     * application may point one connection name at several databases.
     *
     * @throws RuntimeException when the configured guard names no account model
     */
    private function fingerprint(): string
    {
        $model = Uzair::userModel();
        $user = new $model;
        $token = new OauthToken;

        $tokens = $token->getConnection();
        $accounts = $user->getConnection();

        return implode('|', [
            $tokens->getName(),
            $tokens->getDatabaseName(),
            $tokens->getTablePrefix(),
            $token->getTable(),
            $accounts->getName(),
            $accounts->getDatabaseName(),
            $model,
            $user->getTable(),
            $user->getKeyName(),
        ]);
    }

    private function isVerified(string $fingerprint): bool
    {
        if ($this->ttl() === 0) {
            return false;
        }

        if ((self::$verifiedUntil[$fingerprint] ?? 0) > time()) {
            return true;
        }

        try {
            $until = Cache::store()->get($this->cacheKey($fingerprint));
        } catch (Throwable) {
            return false;
        }

        if (! is_int($until) || $until <= time()) {
            return false;
        }

        self::$verifiedUntil[$fingerprint] = $until;

        return true;
    }

    private function rememberVerified(string $fingerprint): void
    {
        $ttl = $this->ttl();

        if ($ttl === 0) {
            return;
        }

        $until = time() + $ttl;

        self::$verifiedUntil[$fingerprint] = $until;

        try {
            Cache::store()->put($this->cacheKey($fingerprint), $until, $ttl);
        } catch (Throwable) {
            // The next process checks the schema itself, which is all this saves.
        }
    }

    private function cacheKey(string $fingerprint): string
    {
        return 'uzairid:storage:'.hash('sha256', $fingerprint);
    }

    /**
     * How long a verified storage is trusted, in seconds; zero checks every time.
     */
    private function ttl(): int
    {
        $ttl = config('uzairports.storage_check_ttl', 3600);

        return max(is_numeric($ttl) ? (int) $ttl : 3600, 0);
    }
}
