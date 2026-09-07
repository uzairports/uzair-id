<?php

namespace Uzairports\Uzairid\Providers;

use Illuminate\Contracts\Container\BindingResolutionException;
use Illuminate\Routing\Router;
use Illuminate\Support\ServiceProvider;
use Laravel\Socialite\Contracts\Factory;
use Uzairports\Uzairid\Http\Middleware\EnsureAccessTokenIsFresh;
use Uzairports\Uzairid\Socialite\UzairportsProvider;

class UzairServiceProvider extends ServiceProvider
{
    /**
     * Register services.
     *
     * The configuration is merged rather than required, so the package works
     * on its defaults and only has to be published to be changed.
     */
    public function register(): void
    {
        $this->mergeConfigFrom($this->configPath(), 'uzairports');
    }

    /**
     * Bootstrap services.
     *
     * @throws BindingResolutionException
     */
    public function boot(): void
    {
        $socialite = $this->app->make(Factory::class);

        $socialite->extend('uzairports', function ($app) use ($socialite) {
            return $socialite->buildProvider(
                UzairportsProvider::class,
                $app['config']['uzairports']
            );
        });

        $this->app->make(Router::class)->aliasMiddleware('uzair.token', EnsureAccessTokenIsFresh::class);

        $this->publishes([
            $this->configPath() => config_path('uzairports.php'),
        ], 'uzairid-config');

        // The publisher stamps each file with a timestamp one second apart, in the
        // order listed here, so this order is the order the migrations run in.
        $this->publishesMigrations([
            __DIR__.'/../database/migrations/remove_password_column_from_users_table.php' => database_path('migrations/'.date('Y_m_d_His', time()).'_remove_password_column_from_users_table.php'),
            __DIR__.'/../database/migrations/add_uzair_id_to_users_table.php' => database_path('migrations/'.date('Y_m_d_His', time()).'_add_uzair_id_to_users_table.php'),
            __DIR__.'/../database/migrations/relax_email_column_on_users_table.php' => database_path('migrations/'.date('Y_m_d_His', time()).'_relax_email_column_on_users_table.php'),
            __DIR__.'/../database/migrations/create_oauth_tokens_table.php' => database_path('migrations/'.date('Y_m_d_His', time()).'_create_oauth_tokens_table.php'),
        ]);
    }

    private function configPath(): string
    {
        return __DIR__.'/../config/uzairports.php';
    }
}
