<?php

namespace Uzairports\Uzairid\Actions;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\QueryException;
use Illuminate\Database\Schema\Builder;
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

    /**
     * Whether a token table without a `user_id` foreign key was reported in
     * this process.
     */
    private static bool $reportedTheUnverifiedOwner = false;

    /**
     * The column types `user_id` is stored as when it holds integer keys.
     */
    private const array INTEGER_TYPES = ['integer', 'int', 'bigint', 'smallint', 'mediumint', 'tinyint', 'int2', 'int4', 'int8', 'serial', 'bigserial', 'smallserial'];

    /**
     * The column types `user_id` is stored as when it holds string keys; any
     * key fits one of them.
     */
    private const array STRING_TYPES = ['varchar', 'char', 'bpchar', 'uuid', 'text', 'tinytext', 'mediumtext', 'longtext', 'nvarchar', 'nchar', 'character varying', 'character', 'string'];

    public function forUser(Authenticatable $user): void
    {
        $this();

        if (! Uzair::accountMatchesProvider($user)) {
            $this->refuse('The route account does not belong to the UzAirports provider.');
        }
    }

    /**
     * Check the storage against the accounts of the guard a route names.
     *
     * `uzair.token:admin` behind `auth:admin` serves the accounts of the
     * `admin` guard's provider; checking them against `uzairports.guard`
     * refused every request of a second guard backed by another model.
     *
     * Without a guard this is `forUser()`, and so it is for a guard whose
     * provider names no Eloquent model (`Auth::viaRequest()`, a custom
     * driver): nothing says which accounts it serves, so the configured
     * provider's stand, as they always did.
     *
     * @throws ServiceUnavailableHttpException when the storage or the account does not fit
     */
    public function forGuard(Authenticatable $user, ?string $guard): void
    {
        try {
            $model = $guard === null ? null : Uzair::userModelFor($guard);
        } catch (RuntimeException) {
            $model = null;
        }

        if ($guard === null || $model === null) {
            $this->forUser($user);

            return;
        }

        $this->verify($model);

        if (! Uzair::accountMatchesProvider($user, $guard)) {
            $this->refuse("The route account does not belong to the provider of the [{$guard}] guard.");
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
        $this->verify(null);
    }

    /**
     * Check the storage against an account model, or against the configured
     * provider's when none is given.
     *
     * @param  class-string<Model>|null  $model
     *
     * @throws ServiceUnavailableHttpException when the storage does not fit
     */
    private function verify(?string $model): void
    {
        try {
            $fingerprint = $this->fingerprint($model ?? Uzair::userModel());
        } catch (RuntimeException $exception) {
            $this->refuse($exception->getMessage());
        }

        if ($this->isVerified($fingerprint)) {
            return;
        }

        try {
            $problem = $model === null ? $this->problem() : $this->problemFor($model);
        } catch (QueryException $exception) {
            // A database failure is not a configuration problem, and its message
            // names hosts, users and SQL: it is logged, never sent to the client.
            Log::error('The UzAirports token storage could not be checked.', [
                'exception_class' => $exception::class,
                'message' => $exception->getMessage(),
            ]);

            throw $this->unavailable();
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
            Cache::store()->forget($this->cacheKey($this->fingerprint(Uzair::userModel())));
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
     * Forget that a table without a `user_id` foreign key was reported, so a
     * test can assert on the warning.
     */
    public static function flushStorageWarnings(): void
    {
        self::$reportedTheUnverifiedOwner = false;
    }

    /**
     * What is wrong with the token storage for the configured provider, if anything.
     */
    public function problem(): ?string
    {
        return $this->problemFor(Uzair::userModel());
    }

    /**
     * What is wrong with the token storage for the given account model, if anything.
     *
     * The existing foreign key is the evidence of which accounts own these ids,
     * so one pointing elsewhere is refused: never reinterpret existing rows
     * after a guard or model configuration change.
     *
     * A table without one is accepted when `user_id` can hold the model's keys,
     * and reported once per process. `create_oauth_tokens_table` writes such a
     * column on purpose when the accounts table does not exist yet or its key
     * cannot be read, and the installation guide promises those installations
     * keep working; refusing them answered every request with a 503. What is
     * given up is the check above — that is what the warning says.
     *
     * @param  class-string<Model>  $model
     */
    public function problemFor(string $model): ?string
    {
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

        if (Uzair::oidcEnabled() && ! $schema->hasColumns($token->getTable(), ['sid', 'id_token'])) {
            return 'OpenID Connect is enabled, but the UzAirports token table has no sid and id_token columns. Run php artisan vendor:publish --tag=uzairid-upgrade-migrations and php artisan migrate.';
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

        return $this->unconstrainedOwnerProblem($schema, $token->getTable(), $user);
    }

    /**
     * Accept a `user_id` without a foreign key when its type can hold the
     * account model's keys: a string column holds any key, an integer column
     * only integer ones.
     */
    private function unconstrainedOwnerProblem(Builder $schema, string $table, Model $user): ?string
    {
        $column = array_find($schema->getColumns($table), fn (array $column): bool => $column['name'] === 'user_id');

        if ($column === null) {
            return 'The UzAirports token table has no user_id column. Publish and run the package migrations.';
        }

        $type = strtolower($column['type_name']);
        $integerKeys = in_array($user->getKeyType(), ['int', 'integer'], true);

        $fits = in_array($type, self::STRING_TYPES, true)
            || (in_array($type, self::INTEGER_TYPES, true) && $integerKeys);

        if (! $fits) {
            $keys = $integerKeys ? 'integer' : 'string';

            return "The UzAirports token table stores user_id as [{$type}], which cannot hold the {$keys} keys of [".$user::class.']. Run php artisan uzair:provider.';
        }

        if (! self::$reportedTheUnverifiedOwner) {
            self::$reportedTheUnverifiedOwner = true;

            Log::warning('The UzAirports token table has no user_id foreign key, so which accounts own its rows cannot be verified. Its rows are read as ids of the configured account model; change that model only through php artisan uzair:provider.', [
                'table' => $table,
                'user_id_type' => $type,
                'account_model' => $user::class,
            ]);
        }

        return null;
    }

    /**
     * Log what is wrong and answer 503.
     *
     * The problem names tables, models and artisan commands, and Laravel shows
     * an HTTP exception's message even with debug off, so it stays in the log.
     *
     * @throws ServiceUnavailableHttpException always
     */
    private function refuse(string $problem): never
    {
        Log::error($problem);

        throw $this->unavailable();
    }

    private function unavailable(): ServiceUnavailableHttpException
    {
        return new ServiceUnavailableHttpException(null, __('uzairid::messages.temporarily_unavailable'));
    }

    /**
     * What the answer of `problem()` depends on, read without a query.
     *
     * The database name and the table prefix are part of it: a multi-tenant
     * application may point one connection name at several databases.
     *
     * @param  class-string<Model>  $model
     */
    private function fingerprint(string $model): string
    {
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
            Uzair::oidcEnabled() ? 'oidc' : 'oauth',
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
