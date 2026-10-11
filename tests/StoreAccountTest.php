<?php

namespace Uzairports\Uzairid\Tests;

use Exception;
use Illuminate\Database\Events\TransactionRolledBack;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Database\UniqueConstraintViolationException;
use Illuminate\Foundation\Application;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Schema;
use Laravel\Socialite\Two\User as SocialiteUser;
use Mockery;
use RuntimeException;
use Uzairports\Uzairid\Actions\StoreAccount;
use Uzairports\Uzairid\Uzair;

class StoreAccountTest extends TestCase
{
    /**
     * @param  Application  $app
     */
    protected function defineEnvironment($app): void
    {
        parent::defineEnvironment($app);

        $app['config']->set('database.connections.accounts', [
            'driver' => 'sqlite',
            'database' => ':memory:',
            'prefix' => '',
        ]);
        $app['config']->set('auth.providers.users.model', AccountOnItsOwnConnection::class);
    }

    protected function tearDown(): void
    {
        Uzair::resolveUserUsing(null);

        parent::tearDown();
    }

    /**
     * The accounts may live on a connection of their own; a transaction opened
     * on the default one left a half-written account behind.
     */
    public function test_a_failed_write_is_rolled_back_on_the_connection_the_accounts_live_on(): void
    {
        Schema::connection('accounts')->create('users', function (Blueprint $table) {
            $table->id();
            $table->string('uzair_id')->nullable()->unique();
            $table->string('name')->nullable();
            $table->string('email')->nullable();
            $table->timestamps();
        });

        Uzair::resolveUserUsing(function (): never {
            AccountOnItsOwnConnection::query()->create(['uzair_id' => '8001']);

            throw new RuntimeException('The resolver failed after writing.');
        });

        try {
            app(StoreAccount::class)(SocialiteUser::fake(['id' => '8001']));

            $this->fail('The failure was not rethrown.');
        } catch (RuntimeException $exception) {
            $this->assertSame('The resolver failed after writing.', $exception->getMessage());
        }

        $this->assertSame(0, AccountOnItsOwnConnection::query()->count());
    }

    /**
     * Two first sign-ins of one identity: the loser's retry finds the account
     * the winner committed.
     */
    public function test_losing_the_race_to_create_the_account_retries_and_finds_it(): void
    {
        $this->createAccountsTable();

        $attempts = 0;

        Uzair::resolveUserUsing(function () use (&$attempts): AccountOnItsOwnConnection {
            if (++$attempts === 1) {
                // The winner commits once this attempt has been rolled back.
                Event::listen(TransactionRolledBack::class, function (): void {
                    AccountOnItsOwnConnection::query()->create(['uzair_id' => '8002', 'email' => 'winner@uzairports.com']);
                });

                throw $this->uniqueViolation('users.uzair_id');
            }

            return AccountOnItsOwnConnection::query()->where('uzair_id', '8002')->firstOrFail();
        });

        $account = app(StoreAccount::class)(SocialiteUser::fake(['id' => '8002']));

        $this->assertSame(2, $attempts);
        $this->assertSame('winner@uzairports.com', $account->getAttribute('email'));
    }

    /**
     * An address another account holds under a unique index is not a
     * concurrent sign-in: no retry can get past it, so it is diagnosed and
     * rethrown at once.
     */
    public function test_a_unique_violation_on_another_column_is_not_retried(): void
    {
        $this->createAccountsTable();
        Log::shouldReceive('error')->once()->with('The account behind an UzAirports identity could not be written.', Mockery::type('array'));

        $attempts = 0;

        Uzair::resolveUserUsing(function () use (&$attempts): never {
            $attempts++;

            throw $this->uniqueViolation('users.email');
        });

        try {
            app(StoreAccount::class)(SocialiteUser::fake(['id' => '8003']));

            $this->fail('The refusal was not rethrown.');
        } catch (UniqueConstraintViolationException) {
            // Expected.
        }

        $this->assertSame(1, $attempts);
    }

    private function createAccountsTable(): void
    {
        Schema::connection('accounts')->create('users', function (Blueprint $table) {
            $table->id();
            $table->string('uzair_id')->nullable()->unique();
            $table->string('name')->nullable();
            $table->string('email')->nullable();
            $table->timestamps();
        });
    }

    private function uniqueViolation(string $column): UniqueConstraintViolationException
    {
        return new UniqueConstraintViolationException(
            'accounts',
            'insert into "users" ("uzair_id") values (?)',
            [],
            new Exception("UNIQUE constraint failed: {$column}"),
        );
    }
}

class AccountOnItsOwnConnection extends Authenticatable
{
    protected $connection = 'accounts';

    protected $table = 'users';

    protected $guarded = [];
}
