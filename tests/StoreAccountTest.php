<?php

namespace Uzairports\Uzairid\Tests;

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Foundation\Application;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Support\Facades\Schema;
use Laravel\Socialite\Two\User as SocialiteUser;
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
}

class AccountOnItsOwnConnection extends Authenticatable
{
    protected $connection = 'accounts';

    protected $table = 'users';

    protected $guarded = [];
}
