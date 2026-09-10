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
use Uzairports\Uzairid\Console\Commands\PruneCommand;
use Uzairports\Uzairid\Http\Middleware\EnsureAccessTokenIsFresh;
use Uzairports\Uzairid\Socialite\UzairportsProvider;
use Uzairports\Uzairid\Uzair;

class UzairServiceProvider extends ServiceProvider
{
    /**
     * The interface behind every one of Octane's terminating events.
     *
     * Named as a string rather than imported: `laravel/octane` is not a
     * dependency of this package, and the interface is absent on every runtime
     * that is not Octane. A listener is registered under a name, so it need
     * not be.
     */
    private const string OCTANE_OPERATION_TERMINATED = 'Laravel\Octane\Contracts\OperationTerminated';

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
     * Only what a request may actually need is done here. The driver is
     * registered against a Socialite manager built when something asks
     * for one, and the publishing groups are declared where publishing can be
     * asked for — a request that never signs anybody in pays for neither.
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
            ]);
        }
    }

    /**
     * Teach Socialite about the `uzairports` driver, once someone wants one.
     *
     * Resolving the manager here would build it on every request the host
     * application serves, including the overwhelming majority that never reach
     * an OAuth endpoint. The registration is deferred to the moment a manager
     * is actually built instead, and `callAfterResolving()` covers the case
     * where another provider has already built one before this one booted.
     */
    private function registerSocialiteDriver(): void
    {
        // Socialite rebinds the closure to the manager, so `$this` inside it is
        // no longer this provider. The configuration step is captured up front
        // as a bound callable rather than reached for through `$this`.
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
     * Have the package's per-request static state dropped between requests.
     *
     * Under PHP-FPM there is nothing to do: the process ends with the response.
     * Under Octane the worker is reused, so a pruner resolved out of a
     * container that has since been rebound would be handed to the next
     * request, and the once-per-process warnings about the login cache and the
     * lock store would stay marked for the life of the worker.
     *
     * `OperationTerminated` is the interface all of Octane's terminating events
     * implement, so the one listener covers requests, tasks, and ticks —
     * Laravel's dispatcher matches an object event against the interfaces it
     * implements as readily as against its class.
     *
     * The listener is registered whether Octane is installed. Nothing
     * else dispatches an event implementing that interface, so on every other
     * runtime this is one entry in the dispatcher's array that never fires —
     * cheaper than the `interface_exists()` call it would take to avoid it, and
     * it leaves the wiring testable without adding Octane as a dependency.
     *
     * What the listener calls is public, so an application on another
     * long-lived runtime can reach `Uzair::flushState()` from wherever that
     * runtime says a request is over.
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
     * Every group here builds its destination paths eagerly — four of them time
     * stamp a migration filename apiece — and none of them can be asked for
     * outside the console, so it is declared there and nowhere else.
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
        ], 'uzairid-upgrade-migrations');
    }

    /**
     * The limiter behind the `uzairid` throttle the package's routes use.
     *
     * The budget is counted per browser rather than per address. An office
     * behind one NAT gateway is a single address to the server, so a per-address
     * limit low enough to be worth having would lock everyone out the moment a
     * handful of colleagues signed in at once.
     *
     * What a browser is, though, is decided by the cookie the request carries,
     * and a caller writes its own cookies. One arriving with a fresh session id
     * every time lands in a fresh bucket every time. The per-browser budget
     * never catches it — so the address it comes from is given a ceiling of its
     * own, which is the limit that actually holds for a caller like that.
     *
     * The ceiling used to be ten times the per-browser budget, which on the
     * defaults left an address free to spend six hundred requests a minute on
     * endpoints that write to the database and call the identity provider. It
     * is configured in its own right now — `routes.ip_throttle`, an
     * `attempts,minutes` pair like the other — so raising what one browser may
     * do no longer quietly raises what one address may do tenfold. Set it to
     * null to leave the address uncapped.
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
     * A request carrying no session cookie is counted against its address
     * instead. The key is spelled apart from the one the address ceiling uses,
     * so such a request is counted in each of them once rather than spending
     * one bucket twice.
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
        return __DIR__.'/../../config/uzairports.php';
    }

    private function langPath(): string
    {
        return __DIR__.'/../../lang';
    }
}
