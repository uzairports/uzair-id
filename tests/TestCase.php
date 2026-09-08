<?php

namespace Uzairports\Uzairid\Tests;

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Foundation\Application;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Routing\Router;
use Illuminate\Support\Facades\Schema;
use Laravel\Socialite\SocialiteServiceProvider;
use Orchestra\Testbench\TestCase as Orchestra;
use Uzairports\Uzairid\Concerns\HasUzairToken;
use Uzairports\Uzairid\Models\OauthToken;
use Uzairports\Uzairid\Providers\UzairServiceProvider;
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
        $app['config']->set('database.default', 'testing');
        $app['config']->set('database.connections.testing', [
            'driver' => 'sqlite',
            'database' => ':memory:',
            'prefix' => '',
        ]);
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

    protected function setUpDatabase(): void
    {
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
