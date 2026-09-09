<?php

namespace Uzairports\Uzairid\Providers;

use Illuminate\Cache\RateLimiting\Limit;
use Illuminate\Contracts\Container\BindingResolutionException;
use Illuminate\Http\Request;
use Illuminate\Routing\Router;
use Illuminate\Support\Facades\RateLimiter;
use Illuminate\Support\ServiceProvider;
use Laravel\Socialite\Contracts\Factory;
use Uzairports\Uzairid\Console\Commands\PruneCommand;
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
     * Apply the settings Socialite cannot read from the driver configuration.
     *
     * `buildProvider()` only understands the client credentials and the
     * redirect, so the host, the scopes, and PKCE are set on the instance it
     * returns. PKCE binds the authorization code to a one-time verifier held
     * in the session, which is what stops an intercepted code being redeemed
     * by anyone but the browser that asked for it.
     *
     * @param  array<string, mixed>  $config
     */
    private function configureProvider(UzairportsProvider $provider, array $config): UzairportsProvider
    {
        if (is_string($config['host'] ?? null) && $config['host'] !== '') {
            $provider->setHost($config['host']);
        }

        if (is_array($config['scopes'] ?? null) && $config['scopes'] !== []) {
            $provider->setScopes($config['scopes']);
        }

        if ($config['pkce'] ?? true) {
            $provider->enablePKCE();
        }

        return $provider;
    }

    /**
     * Bootstrap services.
     *
     * @throws BindingResolutionException
     */
    public function boot(): void
    {
        $socialite = $this->app->make(Factory::class);

        // Socialite rebinds the closure to the manager, so `$this` inside it is
        // no longer this provider. The configuration step is captured up front
        // as a bound callable rather than reached for through `$this`.
        $configureProvider = $this->configureProvider(...);
        $seconds = $this->seconds(...);

        $socialite->extend('uzairports', function ($app) use ($socialite, $configureProvider, $seconds) {
            /** @var array<string, mixed> $config */
            $config = $app['config']['uzairports'] ?? [];

            $guzzle = (array) ($config['guzzle'] ?? []);
            $config['guzzle'] = array_merge($guzzle, [
                'timeout' => $seconds($guzzle['timeout'] ?? $config['timeout'] ?? null, 10),
                'connect_timeout' => $seconds($guzzle['connect_timeout'] ?? $config['connect_timeout'] ?? null, 5),
            ]);

            /** @var UzairportsProvider $provider */
            $provider = $socialite->buildProvider(
                UzairportsProvider::class,
                $config
            );

            return $configureProvider($provider, $config);
        });

        $this->app->make(Router::class)->aliasMiddleware('uzair.token', EnsureAccessTokenIsFresh::class);

        $this->registerRateLimiter();

        $this->loadTranslationsFrom($this->langPath(), 'uzairid');

        $this->publishes([
            $this->configPath() => config_path('uzairports.php'),
        ], 'uzairid-config');

        $this->publishes([
            $this->langPath() => $this->app->langPath('vendor/uzairid'),
        ], 'uzairid-lang');

        $time = time();

        $this->publishesMigrations([
            __DIR__.'/../database/migrations/add_uzair_id_to_users_table.php' => database_path('migrations/'.date('Y_m_d_His', $time++).'_add_uzair_id_to_users_table.php'),
            __DIR__.'/../database/migrations/create_oauth_tokens_table.php' => database_path('migrations/'.date('Y_m_d_His', $time++).'_create_oauth_tokens_table.php'),
        ], 'uzairid-migrations');

        $this->publishesMigrations([
            __DIR__.'/../database/migrations/remove_password_column_from_users_table.php' => database_path('migrations/'.date('Y_m_d_His', $time++).'_remove_password_column_from_users_table.php'),
            __DIR__.'/../database/migrations/relax_email_column_on_users_table.php' => database_path('migrations/'.date('Y_m_d_His', $time++).'_relax_email_column_on_users_table.php'),
        ], 'uzairid-user-migrations');

        $this->publishesMigrations([
            __DIR__.'/../database/migrations/add_session_id_to_oauth_tokens_table.php' => database_path('migrations/'.date('Y_m_d_His', $time++).'_add_session_id_to_oauth_tokens_table.php'),
            __DIR__.'/../database/migrations/make_oauth_tokens_per_session.php' => database_path('migrations/'.date('Y_m_d_His', $time++).'_make_oauth_tokens_per_session.php'),
            __DIR__.'/../database/migrations/index_oauth_tokens_for_pruning.php' => database_path('migrations/'.date('Y_m_d_His', $time++).'_index_oauth_tokens_for_pruning.php'),
            __DIR__.'/../database/migrations/index_oauth_tokens_by_session.php' => database_path('migrations/'.date('Y_m_d_His', $time++).'_index_oauth_tokens_by_session.php'),
        ], 'uzairid-upgrade-migrations');

        if ($this->app->runningInConsole()) {
            $this->commands([
                PruneCommand::class,
            ]);
        }
    }

    /**
     * The limiter behind the `uzairid` throttle the package's routes use.
     *
     * The budget is counted per browser rather than per address. An office
     * behind one NAT gateway is a single address to the server, so a per-address
     * limit low enough to be worth having would lock everyone out the moment a
     * handful of colleagues signed in at once.
     *
     * An address still gets a ceiling — ten times the per-browser budget — for
     * the client that ignores cookies and would otherwise arrive with a fresh
     * session on every request.
     */
    private function registerRateLimiter(): void
    {
        RateLimiter::for('uzairid', function (Request $request): array|Limit {
            $throttle = config('uzairports.routes.throttle', '60,1');

            if (! is_string($throttle) || $throttle === '') {
                return Limit::none();
            }

            [$attempts, $minutes] = array_pad(array_map('trim', explode(',', $throttle)), 2, '1');

            $attempts = max((int) $attempts, 1);
            $minutes = max((int) $minutes, 1);

            return [
                Limit::perMinutes($minutes, $attempts)->by($this->browserKey($request)),
                Limit::perMinutes($minutes, $attempts * 10)->by((string) $request->ip()),
            ];
        });
    }

    /**
     * What counts as one browser for the limit.
     */
    private function browserKey(Request $request): string
    {
        $sessionCookie = config('session.cookie');

        return $request->hasSession() && is_string($sessionCookie) && $request->cookies->has($sessionCookie)
            ? 'session:'.$request->session()->getId()
            : 'ip:'.$request->ip();
    }

    /**
     * Read a configured number of seconds, falling back where there is none.
     *
     * A timeout that is not a number is a misconfiguration, and casting one
     * would read as zero — which Guzzle takes to mean "wait forever", turning a
     * slow identity provider into a hung request. The default stands instead.
     */
    private function seconds(mixed $value, int $default): int
    {
        return is_numeric($value) && (float) $value > 0 ? (int) ceil((float) $value) : $default;
    }

    private function configPath(): string
    {
        return __DIR__.'/../config/uzairports.php';
    }

    private function langPath(): string
    {
        return __DIR__.'/../lang';
    }
}
