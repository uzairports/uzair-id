<?php

namespace Uzairports\Uzairid\Tests;

use GuzzleHttp\Promise\Create;
use GuzzleHttp\Promise\PromiseInterface;
use GuzzleHttp\Psr7\Response;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Foundation\Application;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Routing\Router;
use Illuminate\Support\Facades\Schema;
use Laravel\Socialite\Facades\Socialite;
use Laravel\Socialite\SocialiteServiceProvider;
use Mockery;
use Orchestra\Testbench\TestCase as Orchestra;
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

    protected function setUpDatabase(): void
    {
        Schema::disableForeignKeyConstraints();

        Schema::dropIfExists('oauth_tokens');
        Schema::dropIfExists('sessions');
        Schema::dropIfExists('users');

        Schema::enableForeignKeyConstraints();

        Schema::create('users', function (Blueprint $table) {
            $table->id();
            $table->string('uzair_id')->nullable()->unique();
            $table->string('name')->nullable();
            $table->string('email')->nullable();
            $table->timestamps();
        });

        Schema::create('oauth_tokens', function (Blueprint $table) {
            $table->id();
            $table->foreignId('user_id')->constrained()->cascadeOnDelete()->cascadeOnUpdate();
            $table->text('access_token');
            $table->text('refresh_token')->nullable();
            $table->timestamp('expires_at')->nullable();
            $table->string('session_id')->nullable();
            $table->string('ip_address', 45)->nullable();
            $table->text('user_agent')->nullable();
            $table->timestamps();

            $table->unique(['user_id', 'session_id']);
            $table->index('updated_at');
            $table->index('session_id');
        });

        Schema::create('sessions', function (Blueprint $table) {
            $table->string('id')->primary();
            $table->foreignId('user_id')->nullable()->index();
            $table->string('ip_address', 45)->nullable();
            $table->text('user_agent')->nullable();
            $table->longText('payload');
            $table->integer('last_activity')->index();
        });
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
