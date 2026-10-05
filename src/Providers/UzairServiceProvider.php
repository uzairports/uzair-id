<?php

namespace Uzairports\Uzairid\Providers;

use Illuminate\Cache\RateLimiting\Limit;
use Illuminate\Contracts\Container\BindingResolutionException;
use Illuminate\Http\Request;
use Illuminate\Routing\Router;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\RateLimiter;
use Illuminate\Support\ServiceProvider;
use Laravel\Socialite\Contracts\Factory;
use Laravel\Socialite\SocialiteManager;
use Symfony\Component\HttpFoundation\Response;
use Uzairports\Uzairid\Console\Commands\ProviderCommand;
use Uzairports\Uzairid\Console\Commands\PruneCommand;
use Uzairports\Uzairid\Http\Middleware\EnsureAccessTokenIsFresh;
use Uzairports\Uzairid\Socialite\UzairportsProvider;
use Uzairports\Uzairid\Uzair;

class UzairServiceProvider extends ServiceProvider
{
    /**
     * The interface behind every one of Octane's terminating events.
     *
     * A string, not an import: `laravel/octane` is not a dependency.
     */
    private const string OCTANE_OPERATION_TERMINATED = 'Laravel\Octane\Contracts\OperationTerminated';

    /**
     * Register services.
     */
    public function register(): void
    {
        $this->mergeConfigFrom($this->configPath(), 'uzairports');
    }

    /**
     * Apply the settings Socialite cannot read from the driver configuration.
     *
     * `buildProvider()` only reads credentials and the redirect, so the host,
     * scopes, and PKCE are set here. PKCE (on by default) stops an intercepted
     * code being redeemed by any browser but the one that requested it.
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
        $this->registerSocialiteDriver();

        $this->app->make(Router::class)->aliasMiddleware('uzair.token', EnsureAccessTokenIsFresh::class);

        $this->registerRateLimiter();

        $this->registerStateFlushing();

        $this->loadTranslationsFrom($this->langPath(), 'uzairid');

        if ($this->app->runningInConsole()) {
            $this->registerPublishing();

            $this->commands([
                PruneCommand::class,
                ProviderCommand::class,
            ]);
        }
    }

    /**
     * Register the `uzairports` Socialite driver lazily.
     *
     * The manager must not be resolved during boot, or it is built on every
     * request. `callAfterResolving()` registers the driver when the manager is
     * built, including one built before this provider booted.
     */
    private function registerSocialiteDriver(): void
    {
        // Socialite rebinds the closure to the manager, so helpers are captured
        // as callables rather than reached through `$this`.
        $configureProvider = $this->configureProvider(...);
        $seconds = $this->seconds(...);

        $this->callAfterResolving(Factory::class, function (SocialiteManager $socialite) use ($configureProvider, $seconds): void {
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
        });
    }

    /**
     * Call `Uzair::flushState()` after each Octane request, task, and tick.
     *
     * One listener on Octane's `OperationTerminated` interface covers all of
     * them. It is registered unconditionally: without Octane it never fires,
     * and the wiring stays testable without Octane installed.
     */
    private function registerStateFlushing(): void
    {
        Event::listen(self::OCTANE_OPERATION_TERMINATED, static function (): void {
            Uzair::flushState();
        });
    }

    /**
     * Declare what `vendor:publish` may copy out of the package.
     *
     * Called only in the console: the groups build their destination paths
     * eagerly, and publishing cannot be requested elsewhere.
     */
    private function registerPublishing(): void
    {
        $this->publishes([
            $this->configPath() => config_path('uzairports.php'),
        ], 'uzairid-config');

        $this->publishes([
            $this->langPath() => $this->app->langPath('vendor/uzairid'),
        ], 'uzairid-lang');

        $time = time();

        $this->publishesMigrations([
            __DIR__.'/../../database/migrations/add_uzair_id_to_users_table.php' => database_path('migrations/'.date('Y_m_d_His', $time++).'_add_uzair_id_to_users_table.php'),
            __DIR__.'/../../database/migrations/create_oauth_tokens_table.php' => database_path('migrations/'.date('Y_m_d_His', $time++).'_create_oauth_tokens_table.php'),
        ], 'uzairid-migrations');

        $this->publishesMigrations([
            __DIR__.'/../../database/migrations/remove_password_column_from_users_table.php' => database_path('migrations/'.date('Y_m_d_His', $time++).'_remove_password_column_from_users_table.php'),
            __DIR__.'/../../database/migrations/relax_email_column_on_users_table.php' => database_path('migrations/'.date('Y_m_d_His', $time++).'_relax_email_column_on_users_table.php'),
        ], 'uzairid-user-migrations');

        $this->publishesMigrations([
            __DIR__.'/../../database/migrations/add_session_id_to_oauth_tokens_table.php' => database_path('migrations/'.date('Y_m_d_His', $time++).'_add_session_id_to_oauth_tokens_table.php'),
            __DIR__.'/../../database/migrations/make_oauth_tokens_per_session.php' => database_path('migrations/'.date('Y_m_d_His', $time++).'_make_oauth_tokens_per_session.php'),
            __DIR__.'/../../database/migrations/index_oauth_tokens_for_pruning.php' => database_path('migrations/'.date('Y_m_d_His', $time++).'_index_oauth_tokens_for_pruning.php'),
            __DIR__.'/../../database/migrations/index_oauth_tokens_by_session.php' => database_path('migrations/'.date('Y_m_d_His', $time++).'_index_oauth_tokens_by_session.php'),
            __DIR__.'/../../database/migrations/add_personal_access_token_id_to_oauth_tokens_table.php' => database_path('migrations/'.date('Y_m_d_His', $time++).'_add_personal_access_token_id_to_oauth_tokens_table.php'),
        ], 'uzairid-upgrade-migrations');
    }

    /**
     * The limiter behind the `uzairid` throttle the package's routes use.
     *
     * `routes.throttle` is counted per browser, so many users behind one NAT
     * address are not locked out together. Since a caller can rotate its
     * session cookie, `routes.ip_throttle` adds an independent per-address
     * ceiling (null disables it). Keep the two budgets independent.
     */
    private function registerRateLimiter(): void
    {
        RateLimiter::for('uzairid', function (Request $request): array|Limit {
            $throttle = config('uzairports.routes.throttle', '60,1');

            if (! is_string($throttle) || $throttle === '') {
                return Limit::none();
            }

            $responseCallback = function (Request $request, array $headers): Response {
                $message = __('uzairid::messages.rate_limited');

                if ($request->expectsJson()) {
                    return response()->json(['message' => $message], 429, $headers);
                }

                if ($request->hasSession() && $request->headers->has('referer')) {
                    $referer = (string) $request->headers->get('referer');

                    if ($referer !== $request->fullUrl()) {
                        return back()->withErrors(['oauth' => $message])->withHeaders($headers);
                    }
                }

                return response($message, 429, $headers);
            };

            [$attempts, $minutes] = $this->budget($throttle);

            $limits = [
                Limit::perMinutes($minutes, $attempts)
                    ->by($this->browserKey($request))
                    ->response($responseCallback),
            ];

            $ceiling = config('uzairports.routes.ip_throttle', '120,1');

            if (is_string($ceiling) && $ceiling !== '') {
                [$ceilingAttempts, $ceilingMinutes] = $this->budget($ceiling);

                $limits[] = Limit::perMinutes($ceilingMinutes, $ceilingAttempts)
                    ->by('address:'.$request->ip())
                    ->response($responseCallback);
            }

            return $limits;
        });
    }

    /**
     * Read an `attempts,minutes` pair, refusing a budget that permits nothing.
     *
     * @return array{int<1, max>, int<1, max>}
     */
    private function budget(string $throttle): array
    {
        [$attempts, $minutes] = array_pad(array_map('trim', explode(',', $throttle)), 2, '1');

        return [max((int) $attempts, 1), max((int) $minutes, 1)];
    }

    /**
     * What counts as one browser for the limit.
     *
     * Without a session cookie the address is used, under the `ip:` prefix so
     * it does not share the ceiling's `address:` bucket. The session id is
     * hashed because it is a credential and must not be legible in the cache,
     * even if `ThrottleRequests` key hashing is turned off.
     */
    private function browserKey(Request $request): string
    {
        $sessionCookie = config('session.cookie');

        return $request->hasSession() && is_string($sessionCookie) && $request->cookies->has($sessionCookie)
            ? 'session:'.hash('sha256', $request->session()->getId())
            : 'ip:'.$request->ip();
    }

    /**
     * Read a configured number of seconds, falling back where there is none.
     *
     * A non-numeric or non-positive value uses the default, since Guzzle reads
     * zero as "wait forever".
     */
    private function seconds(mixed $value, int $default): int
    {
        return is_numeric($value) && (float) $value > 0 ? (int) ceil((float) $value) : $default;
    }

    private function configPath(): string
    {
        return __DIR__.'/../../config/uzairports.php';
    }

    private function langPath(): string
    {
        return __DIR__.'/../../lang';
    }
}
