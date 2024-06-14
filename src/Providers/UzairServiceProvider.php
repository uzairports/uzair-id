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
            __DIR__.'/../database/migrations' => database_path('migrations'),
        ]);
        $this->publishes([
            __DIR__.'/../Models' => app_path('Models'),
        ]);
    }
}
