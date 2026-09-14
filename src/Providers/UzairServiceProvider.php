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

        // Socialite rebinds the closure to the manager, so `$this` inside it is
        // no longer this provider. The configuration step is captured up front
        // as a bound callable rather than reached for through `$this`.
        $configureProvider = $this->configureProvider(...);

        $socialite->extend('uzairports', function ($app) use ($socialite, $configureProvider) {
            $config = (array) ($app['config']['services.uzairports'] ?? []);

            /** @var UzairportsProvider $provider */
            $provider = $socialite->buildProvider(UzairportsProvider::class, $config);

            return $configureProvider($provider, $config);
        });

        $this->publishesMigrations([
            __DIR__.'/../database/migrations/remove_password_column_from_users_table.php' => database_path('migrations/'.date('Y_m_d_His', time()).'_remove_password_column_from_users_table.php'),
            __DIR__.'/../database/migrations/create_oauth_tokens_table.php' => database_path('migrations/'.date('Y_m_d_His', time()).'_create_oauth_tokens_table.php'),
        ]);
    }

    /**
     * Apply the settings Socialite cannot read from the driver configuration.
     *
     * `buildProvider()` only understands the client credentials and the
     * redirect, so the host and the scopes are set on the instance it returns.
     * Both are optional: an empty value leaves the driver on its defaults —
     * the production host and whatever scopes the identity provider decides on.
     *
     * @param  array<string, mixed>  $config
     */
    private function configureProvider(UzairportsProvider $provider, array $config): UzairportsProvider
    {
        $host = $config['host'] ?? null;

        if (is_string($host) && trim($host) !== '') {
            $provider->setHost($host);
        }

        $scopes = $this->scopesFrom($config);

        if ($scopes !== []) {
            $provider->setScopes($scopes);
        }

        return $provider;
    }

    /**
     * The scopes requested on the authorization URL.
     *
     * `UZAIR_SCOPES` reaches the configuration as a single string, so a
     * space- or comma-separated list is accepted alongside a plain array.
     *
     * @param  array<string, mixed>  $config
     * @return list<string>
     */
    private function scopesFrom(array $config): array
    {
        $scopes = $config['scopes'] ?? [];

        if (is_string($scopes)) {
            $scopes = preg_split('/[\s,]+/', $scopes) ?: [];
        }

        if (! is_array($scopes)) {
            return [];
        }

        $scopes = array_map(static fn ($scope): string => trim((string) $scope), $scopes);

        return array_values(array_filter($scopes, static fn (string $scope): bool => $scope !== ''));
    }
}
