<?php

namespace Uzairports\Uzairid\Actions;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\QueryException;
use Illuminate\Database\Schema\Builder;
use Illuminate\Database\UniqueConstraintViolationException;
use Illuminate\Support\Facades\Log;
use Laravel\Socialite\Two\User as SocialiteUser;
use RuntimeException;
use Throwable;
use Uzairports\Uzairid\Uzair;

/**
 * Write the local account behind an SSO identity, ready to be signed in.
 *
 * The write is a transaction of its own and the caller signs the account in
 * after it commits: `Auth::login()` fires events whose listeners must see a
 * committed account.
 */
class StoreAccount
{
    public function __construct(private readonly ResolveUserFromSocialite $resolveUser) {}

    /**
     * Resolve and write the account, retrying once if a concurrent sign-in won.
     *
     * Two first sign-ins of one identity both insert; the unique `uzair_id`
     * refuses the loser, whose retry finds the winner's row. Any other refusal
     * is logged with what about the accounts table caused it, then rethrown.
     *
     * @return Authenticatable&Model
     *
     * @throws Throwable
     */
    public function __invoke(SocialiteUser $uzairUser): Authenticatable
    {
        try {
            return $this->write($uzairUser);
        } catch (UniqueConstraintViolationException) {
            // The concurrent sign-in's row is committed now; the retry finds it.
        } catch (QueryException $exception) {
            $this->refuse($exception);
        }

        try {
            return $this->write($uzairUser);
        } catch (QueryException $exception) {
            $this->refuse($exception);
        }
    }

    /**
     * The key an account's logins are filed under.
     *
     * @throws RuntimeException when the account has no integer or string key
     */
    public function keyOf(Authenticatable $user): int|string
    {
        $key = $user->getAuthIdentifier();

        if (! is_int($key) && ! is_string($key)) {
            throw new RuntimeException('The authenticated user has no key that names its logins.');
        }

        return $key;
    }

    /**
     * The account must exist and belong to the configured guard's provider
     * before anybody is signed in as it: `save()` answers false instead of
     * raising when a listener refuses the write, and a guard reloads the
     * stored id through its own provider on the next request.
     *
     * @return Authenticatable&Model
     *
     * @throws RuntimeException when the resolved account cannot be signed in
     * @throws Throwable
     */
    private function write(SocialiteUser $uzairUser): Authenticatable
    {
        return $this->accounts()->getConnection()->transaction(function () use ($uzairUser): Authenticatable {
            $user = ($this->resolveUser)($uzairUser);

            if (! $user instanceof Authenticatable) {
                throw new RuntimeException('The account returned by the UzAirports resolver cannot be authenticated.');
            }

            $this->ensureAccountMatchesGuard($user);

            if (! $user->exists) {
                throw new RuntimeException('The account behind this UzAirports identity was not written.');
            }

            // `single_session` names the account's logins by this key once the
            // caller has signed it in; a key that cannot do that fails here,
            // before anything is signed in.
            if (config('uzairports.single_session', false)) {
                $this->keyOf($user);
            }

            return $user;
        });
    }

    private function ensureAccountMatchesGuard(Authenticatable $user): void
    {
        if (Uzair::accountMatchesProvider($user)) {
            return;
        }

        Log::error('The UzAirports account does not match the configured guard provider.', [
            'guard' => Uzair::guard() ?? config('auth.defaults.guard'),
            'expected_model' => Uzair::userModel(),
            'resolved_model' => $user::class,
        ]);

        throw new RuntimeException('The UzAirports account does not match the configured guard provider.');
    }

    /**
     * Log what about the accounts table refused the write, then rethrow.
     *
     * A standard Laravel `users` table refuses an SSO account twice over:
     * `password` is required, and `email` is required and unique. The schema
     * is read rather than the driver's message parsed, and the diagnosis never
     * replaces the exception it describes.
     *
     * @throws QueryException always
     */
    private function refuse(QueryException $exception): never
    {
        Log::error('The account behind an UzAirports identity could not be written.', [
            'exception_class' => $exception::class,
            ...$this->accountsTableComplaints(),
        ]);

        throw $exception;
    }

    /**
     * @return array<string, mixed>
     */
    private function accountsTableComplaints(): array
    {
        try {
            $accounts = $this->accounts();
            $table = $accounts->getTable();
            $schema = $accounts->getConnection()->getSchemaBuilder();

            return [
                'accounts_table' => $table,
                'email_is_unique' => $schema->hasIndex($table, ['email'], 'unique'),
                'columns_needing_a_value' => $this->columnsNeedingAValue($schema, $table),
                'remedy' => 'php artisan vendor:publish --tag=uzairid-user-migrations',
            ];
        } catch (Throwable) {
            return [];
        }
    }

    /**
     * The columns a new account cannot be written without, beyond those the
     * package fills in.
     *
     * @return list<string>
     */
    private function columnsNeedingAValue(Builder $schema, string $table): array
    {
        $written = ['uzair_id', 'name', 'email', 'created_at', 'updated_at'];

        $needed = [];

        foreach ($schema->getColumns($table) as $column) {
            if (in_array($column['name'], $written, true) || $column['auto_increment']) {
                continue;
            }

            if (! $column['nullable'] && $column['default'] === null) {
                $needed[] = $column['name'];
            }
        }

        return $needed;
    }

    /**
     * An empty account, for the connection and table the accounts live on —
     * which need not be the application's default connection.
     */
    private function accounts(): Model
    {
        $model = Uzair::userModel();

        return new $model;
    }
}
