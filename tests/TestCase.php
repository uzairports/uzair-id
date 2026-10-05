<?php

namespace Uzairports\Uzairid\Tests;

use GuzzleHttp\Promise\Create;
use GuzzleHttp\Promise\PromiseInterface;
use GuzzleHttp\Psr7\Response;
use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Foundation\Application;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Routing\Router;
use Illuminate\Support\Facades\Schema;
use Laravel\Socialite\Facades\Socialite;
use Laravel\Socialite\SocialiteServiceProvider;
use Mockery;
use Orchestra\Testbench\TestCase as Orchestra;
use RuntimeException;
use Uzairports\Uzairid\Actions\EnsureTokenStorageMatchesProvider;
use Uzairports\Uzairid\Concerns\HasUzairToken;
use Uzairports\Uzairid\Models\OauthToken;
use Uzairports\Uzairid\Providers\UzairServiceProvider;
use Uzairports\Uzairid\Socialite\UzairportsProvider;
use Uzairports\Uzairid\Uzair;

abstract class TestCase extends Orchestra
{
    protected function setUp(): void
    {
        parent::setUp();

        EnsureTokenStorageMatchesProvider::flushVerified();

        $this->setUpDatabase();
    }

    /**
     * @param  Application  $app
     * @return array<int, class-string>
     */
    protected function getPackageProviders($app): array
    {
        return [
            SocialiteServiceProvider::class,
            UzairServiceProvider::class,
        ];
    }

    /**
     * @param  Application  $app
     */
    protected function defineEnvironment($app): void
    {
        $app['config']->set('auth.providers.users.model', TestUser::class);

        $driver = getenv('DB_CONNECTION') ?: 'testing';

        if ($driver === 'pgsql') {
            $app['config']->set('database.default', 'pgsql');
            $app['config']->set('database.connections.pgsql', [
                'driver' => 'pgsql',
                'host' => getenv('DB_HOST') ?: '127.0.0.1',
                'port' => getenv('DB_PORT') ?: '5432',
                'database' => getenv('DB_DATABASE') ?: 'test',
                'username' => getenv('DB_USERNAME') ?: 'postgres',
                'password' => getenv('DB_PASSWORD') ?: 'password',
                'charset' => 'utf8',
                'prefix' => '',
                'schema' => 'public',
                'sslmode' => 'prefer',
            ]);
        } elseif ($driver === 'mysql') {
            $app['config']->set('database.default', 'mysql');
            $app['config']->set('database.connections.mysql', [
                'driver' => 'mysql',
                'host' => getenv('DB_HOST') ?: '127.0.0.1',
                'port' => getenv('DB_PORT') ?: '3306',
                'database' => getenv('DB_DATABASE') ?: 'test',
                'username' => getenv('DB_USERNAME') ?: 'root',
                'password' => getenv('DB_PASSWORD') ?: '',
                'charset' => 'utf8mb4',
                'collation' => 'utf8mb4_unicode_ci',
                'prefix' => '',
            ]);
        } else {
            $app['config']->set('database.default', 'testing');
            $app['config']->set('database.connections.testing', [
                'driver' => 'sqlite',
                // In memory whatever `DB_DATABASE` holds: the other two branches
                // read it as a database on a server, and an environment that sets
                // it for them hands SQLite the same value as a path to a file.
                'database' => ':memory:',
                'prefix' => '',
            ]);
        }

        $app['config']->set('uzairports.client_id', 'test-client-id');
        $app['config']->set('uzairports.client_secret', 'test-client-secret');
        $app['config']->set('uzairports.redirect', 'https://app.test/auth/callback');
    }

    /**
     * The routes the package registers, inside the middleware group the OAuth
     * flow needs: the callback regenerates the session, so a route without one
     * would fail on the session rather than on what a test is asserting.
     */
    protected function defineRoutes($router): void
    {
        /** @var Router $router */
        $router->middleware('web')->group(function () use ($router): void {
            Uzair::routes();

            $router->get('dashboard', fn (): string => 'dashboard')->name('dashboard');

            $router->get('protected', fn (): string => 'protected')
                ->middleware(['auth', 'uzair.token'])
                ->name('protected');
        });
    }

    /**
     * The answer a provider gives to a revocation it accepted.
     *
     * Revocations are handed back as promises so that several can be in flight
     * at once, so a mocked provider answers with one too. Confirming the status
     * is the real provider's business and is bypassed by the mock, which stands
     * for a call that already succeeded.
     */
    protected function revoked(): PromiseInterface
    {
        return Create::promiseFor(new Response(200));
    }

    /**
     * Stand in for an identity provider that accepts whatever it is handed.
     *
     * Every path that ends a login surrenders its grants, so a test that ends
     * one while asserting on something else still has to answer for the call —
     * left unanswered it resolves the real driver and leaves the suite for the
     * identity provider itself.
     */
    protected function acceptsRevocations(): void
    {
        $provider = Mockery::mock(UzairportsProvider::class);
        $provider->shouldReceive('logoutAsync')->andReturnUsing(fn (): PromiseInterface => $this->revoked());
        $provider->shouldReceive('revokeRefreshTokenAsync')->andReturnUsing(fn (): PromiseInterface => $this->revoked());

        Socialite::shouldReceive('driver')->with('uzairports')->andReturn($provider);
    }

    /**
     * A statement as the driver wrote it, with its identifier quoting taken off.
     *
     * A listener watching for `delete from "oauth_tokens"` sees nothing on
     * MySQL, which spells the same statement with backticks, and the counter it
     * keeps stays at zero — which an assertion reads as work that never
     * happened rather than as a difference in spelling.
     */
    protected function unquotedSql(string $sql): string
    {
        return trim(strtolower(str_replace(['`', '"'], '', $sql)));
    }

    protected function setUpDatabase(): void
    {
        Schema::disableForeignKeyConstraints();

        Schema::dropIfExists('oauth_tokens');
        Schema::dropIfExists('personal_access_tokens');
        Schema::dropIfExists('sessions');
        Schema::dropIfExists('users');

        Schema::enableForeignKeyConstraints();

        // The accounts table belongs to the host application, so it is written
        // here in the shape the package's user migrations leave it in. Every
        // table the package or Sanctum owns comes from its own migration, so the
        // suite runs against the schema an installation actually gets.
        Schema::create('users', function (Blueprint $table) {
            $table->id();
            $table->string('name')->nullable();
            $table->string('email')->nullable();
            $table->timestamps();
        });

        $this->runMigration(__DIR__.'/../database/migrations/add_uzair_id_to_users_table.php');
        $this->runMigration(__DIR__.'/../database/migrations/create_oauth_tokens_table.php');
        $this->runMigration(__DIR__.'/../vendor/laravel/sanctum/database/migrations/2019_12_14_000001_create_personal_access_tokens_table.php');

        Schema::create('sessions', function (Blueprint $table) {
            $table->string('id')->primary();
            $table->foreignId('user_id')->nullable()->index();
            $table->string('ip_address', 45)->nullable();
            $table->text('user_agent')->nullable();
            $table->longText('payload');
            $table->integer('last_activity')->index();
        });
    }

    private function runMigration(string $path): void
    {
        $migration = require $path;

        if (! $migration instanceof Migration || ! method_exists($migration, 'up')) {
            throw new RuntimeException("[{$path}] is not a runnable migration.");
        }

        $migration->up();
    }
}

/**
 * @property int $id
 * @property string|null $uzair_id
 * @property string|null $name
 * @property string|null $email
 * @property-read OauthToken|null $token
 */
class TestUser extends Authenticatable
{
    use HasUzairToken;

    protected $table = 'users';

    protected $guarded = [];
}
