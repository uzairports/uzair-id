<?php

namespace Uzairports\Uzairid\Providers;

use Illuminate\Support\ServiceProvider;
use Laravel\Socialite\Contracts\Factory;
use Uzairports\Uzairid\Socialite\UzairportsProvider;

class UzairServiceProvider extends ServiceProvider
{
    /**
     * Register services.
     */
    public function register(): void
    {
        //
    }

    /**
     * Bootstrap services.
     */
    public function boot(): void
    {
        $socialite = $this->app->make(Factory::class);

        $socialite->extend('uzairports', function ($app) use($socialite) {
            return $socialite->buildProvider(
                UzairportsProvider::class,
                $app['config']['services.uzairports']
            );
        });

        $this->publishesMigrations([
            __DIR__.'/../database/migrations/remove_password_column_from_users_table.php' => database_path('migrations/'. date('Y_m_d_His', time()) . '_remove_password_column_from_users_table.php'),
            __DIR__.'/../database/migrations/create_oauth_tokens_table.php' => database_path('migrations/'. date('Y_m_d_His', time()) . '_create_oauth_tokens_table.php'),
        ]);
    }
}
