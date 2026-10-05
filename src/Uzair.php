<?php

namespace Uzairports\Uzairid;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\Request;
use Illuminate\Routing\Route as RegisteredRoute;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Route;
use Laravel\Sanctum\Sanctum;
use Laravel\Socialite\Two\User as SocialiteUser;
use RuntimeException;
use Uzairports\Uzairid\Actions\RefreshAccessToken;
use Uzairports\Uzairid\Http\Controllers\UzairApiAuthController;
use Uzairports\Uzairid\Http\Controllers\UzairAuthController;
use Uzairports\Uzairid\Models\OauthToken;

class Uzair
{
    /** @var (callable(SocialiteUser): ?Model)|null */
    protected static $userResolver = null;

    /**
     * Register a custom callback to resolve or update the local user model from the SSO identity.
     *
     * @param  (callable(SocialiteUser): ?Model)|null  $callback
     */
    public static function resolveUserUsing(?callable $callback): void
    {
        static::$userResolver = $callback;
    }

    /**
     * Get the custom user resolver, if registered.
     *
     * @return (callable(SocialiteUser): ?Model)|null
     */
    public static function getUserResolver(): ?callable
    {
        return static::$userResolver;
    }

    /**
     * The guard this package signs in, signs out, and reads the account off.
     *
     * Null means the application's default guard. The endpoints in
     * `UzairAuthController` use this setting; the `uzair.token` middleware
     * takes its own guard parameter (`uzair.token:admin`) instead.
     */
    public static function guard(): ?string
    {
        $guard = config('uzairports.guard');

        return is_string($guard) && $guard !== '' ? $guard : null;
    }

    /**
     * The account model belonging to the provider of the configured guard.
     *
     * @return class-string<Model>
     */
    public static function userModel(): string
    {
        $guard = self::accountGuard(self::guard() ?? config('auth.defaults.guard'));
        $provider = is_string($guard) ? config("auth.guards.{$guard}.provider") : null;
        $model = is_string($provider) ? config("auth.providers.{$provider}.model") : null;

        if (! is_string($model) || ! is_subclass_of($model, Model::class)) {
            throw new RuntimeException('The provider of the configured UzAirports guard has no Eloquent user model.');
        }

        return $model;
    }

    /**
     * The guard whose provider names the accounts behind the given one.
     *
     * Sanctum's guard has no provider and reads accounts through the guards
     * listed in `sanctum.guard`, so the first of those is used instead.
     * `auth:sanctum` makes Sanctum the default guard for the rest of the request.
     */
    private static function accountGuard(mixed $guard): mixed
    {
        if (! is_string($guard)
            || config("auth.guards.{$guard}.driver") !== 'sanctum'
            || config("auth.guards.{$guard}.provider") !== null) {
            return $guard;
        }

        // An API-only Sanctum lists no session guards at all; the application's
        // `web` guard still names the accounts its tokens belong to.
        $guards = array_values(array_filter((array) config('sanctum.guard', ['web']), 'is_string'));

        return $guards[0] ?? (config('auth.guards.web') !== null ? 'web' : $guard);
    }

    /**
     * The guard that authenticates the Sanctum tokens issued to mobile clients,
     * used by the endpoints `apiRoutes()` registers.
     */
    public static function apiGuard(): string
    {
        $guard = config('uzairports.api.guard', 'sanctum');

        return is_string($guard) && $guard !== '' ? $guard : 'sanctum';
    }

    /**
     * The redirect URIs a mobile client may say it obtained its code with.
     *
     * @return list<string>
     */
    public static function apiRedirectUris(): array
    {
        $uris = config('uzairports.api.redirect_uris', []);

        if (! is_array($uris)) {
            return [];
        }

        return array_values(array_filter($uris, fn (mixed $uri): bool => is_string($uri) && $uri !== ''));
    }

    /**
     * The Sanctum token model, or null where Sanctum is not installed.
     *
     * Sanctum is suggested, not required. Honours a model swapped through
     * `Sanctum::usePersonalAccessTokenModel()`.
     *
     * @return class-string<Model>|null
     */
    public static function accessTokenModel(): ?string
    {
        return class_exists(Sanctum::class) ? Sanctum::personalAccessTokenModel() : null;
    }

    /**
     * The key of the Sanctum token the account authenticated this request with.
     *
     * A mobile client's login is filed under that token. Null for a session, a
     * console command, or Sanctum's `TransientToken` (an SPA authenticated by
     * its session cookie), which names no row.
     */
    public static function accessTokenId(?Authenticatable $user): int|string|null
    {
        if ($user === null || ! method_exists($user, 'currentAccessToken')) {
            return null;
        }

        $token = $user->currentAccessToken();

        if (! $token instanceof Model || ! $token->exists) {
            return null;
        }

        $key = $token->getKey();

        return is_int($key) || is_string($key) ? $key : null;
    }

    public static function accountMatchesProvider(Authenticatable $user): bool
    {
        $model = self::userModel();
        $expected = new $model;

        return $user instanceof $model
            && $user->getTable() === $expected->getTable()
            && $user->getKeyName() === $expected->getKeyName()
            && $user->getConnection()->getName() === $expected->getConnection()->getName();
    }

    /**
     * Drop the static state that must not outlive a request on a long-lived
     * worker: the container-resolved `OauthToken` pruner and the once-per-process
     * warning registers (login cache, lock store, login route).
     *
     * The user and local-request resolvers are deliberately kept: they are
     * registered once at boot, and a worker that dropped them would serve every
     * later request without them.
     *
     * `UzairServiceProvider` calls this on Octane's terminating events; other
     * long-lived runtimes should call it at the end of each request.
     */
    public static function flushState(): void
    {
        OauthToken::flushPruner();
        OauthToken::flushAccessTokensTables();
        OauthToken::flushLoginCacheWarnings();
        RefreshAccessToken::flushLockStoreWarnings();
        self::flushLoginRouteWarnings();
    }

    /**
     * Where a browser is sent to sign in through UzAirports ID.
     *
     * The `redirect` endpoint is named by `uzairports.login_route` (default
     * `login`, which `redirectGuestsTo()` and `Authenticate` look for). A route
     * carries only one name, so there is no fixed alias; templates call this
     * instead of `route()`.
     *
     * This is the only place the setting becomes a URL; `uzair.token` uses it
     * too. An unregistered name falls back to the site root rather than a 500,
     * and is logged once per process since templates may call this on every page.
     *
     * @phpstan-impure
     */
    public static function loginUrl(): string
    {
        $route = config('uzairports.login_route', 'login');

        if (! is_string($route) || $route === '') {
            $route = 'login';
        }

        if (Route::has($route)) {
            return route($route);
        }

        if (! isset(self::$reportedAboutTheLoginRoute[$route])) {
            self::$reportedAboutTheLoginRoute[$route] = true;

            Log::warning("The route [{$route}] configured as [uzairports.login_route] is not registered, so anyone sent to sign in lands on the site root instead.");
        }

        return url('/');
    }

    /**
     * The login route names already reported as unregistered in this process.
     *
     * @var array<string, true>
     */
    protected static array $reportedAboutTheLoginRoute = [];

    /**
     * Let the warning be logged again. Called by `flushState()` and by tests.
     */
    public static function flushLoginRouteWarnings(): void
    {
        self::$reportedAboutTheLoginRoute = [];
    }

    /**
     * Session key holding the id this browser's login is filed under.
     */
    private const string SESSION_KEY = 'uzairid.session';

    /**
     * Session/request attribute key marking local (non-SSO) authentication.
     */
    private const string LOCAL_KEY = 'uzairid.local';

    /**
     * Note the session id this browser's login is filed under.
     *
     * `followRegeneratedSession()` compares against this note. It lives in the
     * server-side session payload, which the browser cannot write. Written only
     * when the id changed, so reading does not mark the session dirty.
     */
    public static function rememberSession(Request $request): void
    {
        if (! $request->hasSession()) {
            return;
        }

        $session = $request->session();

        if ($session->get(self::SESSION_KEY) !== $session->getId()) {
            $session->put(self::SESSION_KEY, $session->getId());
        }
    }

    /**
     * Both ids may still name logins when a browser signs in after regeneration.
     * Read them before authentication changes the session and overwrites its note.
     *
     * @return list<string>
     */
    public static function loginSessionIds(Request $request): array
    {
        if (! $request->hasSession()) {
            return [];
        }

        $session = $request->session();
        $previous = $session->get(self::SESSION_KEY);
        $ids = [$session->getId()];

        if (is_string($previous) && $previous !== '' && $previous !== $session->getId()) {
            $ids[] = $previous;
        }

        return $ids;
    }

    /**
     * Take the login with the browser when its session is given a new id.
     *
     * `regenerate()` keeps the payload but changes the id, so a note differing
     * from the current id means the same browser; its login row is moved to the
     * new id. Laravel fires no event on regeneration.
     *
     * The move is scoped to the account, because the note identifies a session,
     * not its owner; a non-int/string key moves nothing. The note is updated
     * regardless, so a login that is really gone is not searched for again.
     *
     * @param  mixed  $userId  the key of the account the session is signed in as
     * @return bool whether a login may now be found under the current id
     */
    public static function followRegeneratedSession(Request $request, mixed $userId): bool
    {
        if (! $request->hasSession() || (! is_int($userId) && ! is_string($userId))) {
            return false;
        }

        $session = $request->session();
        $previous = $session->get(self::SESSION_KEY);

        if (! is_string($previous) || $previous === '' || $previous === $session->getId()) {
            return false;
        }

        $session->put(self::SESSION_KEY, $session->getId());

        return OauthToken::followSession($userId, $previous, $session->getId());
    }

    /**
     * Say that this session was authenticated by the application itself.
     *
     * `uzair.token` refuses a session with no login row when the account has a
     * `uzair_id`; this mark exempts sessions the application authenticated
     * itself (e.g. a password sign-in in a hybrid app). Call it after signing
     * the browser in, since `Auth::attempt()` migrates the session. The mark
     * ends with the session and is removed by an SSO sign-in.
     */
    public static function markSessionAsLocal(Request $request): void
    {
        if ($request->hasSession()) {
            $request->session()->put(self::LOCAL_KEY, true);
        }
    }

    /**
     * Whether this session was authenticated by the application itself.
     */
    public static function sessionIsLocal(Request $request): bool
    {
        return $request->hasSession() && $request->session()->get(self::LOCAL_KEY) === true;
    }

    /**
     * Say how a request with no session of its own was authenticated.
     *
     * The sessionless counterpart of `markSessionAsLocal()`, for API clients
     * and console commands. The callback answers whether the application
     * authenticated the request itself, e.g. by its Sanctum token:
     *
     * ```php
     * Uzair::treatRequestsAsLocalWhen(
     *     fn (Request $request): bool => $request->user()?->currentAccessToken() !== null,
     * );
     * ```
     *
     * Registered once at boot and deliberately not dropped by `flushState()`.
     *
     * @param  (callable(Request): bool)|null  $callback
     */
    public static function treatRequestsAsLocalWhen(?callable $callback): void
    {
        static::$localRequestResolver = $callback;
    }

    /**
     * Say that this one request was authenticated by the application itself.
     *
     * The imperative form of `treatRequestsAsLocalWhen()`, e.g. from the
     * application's own middleware. Stored in the request's attribute bag, so
     * it applies to this request only.
     */
    public static function markRequestAsLocal(Request $request): void
    {
        $request->attributes->set(self::LOCAL_KEY, true);
    }

    /**
     * Whether this request's authentication comes from somewhere but SSO.
     *
     * Checked cheapest first: session mark, request attribute, then the
     * application's callback.
     */
    public static function requestIsLocal(Request $request): bool
    {
        if (self::sessionIsLocal($request) || $request->attributes->get(self::LOCAL_KEY) === true) {
            return true;
        }

        $resolver = static::$localRequestResolver;

        return $resolver !== null && $resolver($request) === true;
    }

    /**
     * How the application says a sessionless request is its own.
     *
     * @var (callable(Request): bool)|null
     */
    protected static $localRequestResolver = null;

    /**
     * Stop a session counting as one the application authenticated itself.
     *
     * Called on SSO sign-in: the session now has a login row, and a leftover
     * local mark would exempt it from the check that notices the login ending.
     */
    public static function forgetLocalSession(Request $request): void
    {
        if ($request->hasSession()) {
            $request->session()->forget(self::LOCAL_KEY);
        }
    }

    /**
     * Register the SSO endpoints.
     *
     * Call from `routes/web.php` so the routes get the session and CSRF
     * middleware. The redirect route is named by `uzairports.login_route`, the
     * same place `uzair.token` sends a session it can no longer renew.
     *
     * Routes use the `uzairid` limiter by default; `throttle` takes another
     * limiter name, an `attempts,minutes` pair, or null for no limit.
     *
     * There is deliberately no "sign out everywhere" endpoint: each login costs
     * a revocation round-trip, and one request cannot pay for an unbounded
     * number. `logout-device` ends one login per request, and its id is
     * constrained to digits so a non-numeric value never reaches the `bigint`
     * comparison (a 500 on PostgreSQL).
     *
     * @param  array{prefix?: string, throttle?: string|null, controller?: class-string, middleware?: array<array-key, mixed>|string}  $options
     */
    public static function routes(array $options = []): void
    {
        $prefix = $options['prefix'] ?? config('uzairports.routes.prefix', 'auth');
        $throttle = array_key_exists('throttle', $options) ? $options['throttle'] : 'uzairid';
        $controller = $options['controller'] ?? UzairAuthController::class;

        $loginRoute = config('uzairports.login_route', 'login');

        if (! is_string($loginRoute) || $loginRoute === '') {
            $loginRoute = 'login';
        }

        $group = Route::prefix(is_string($prefix) ? $prefix : 'auth');

        $middleware = (array) ($options['middleware'] ?? []);

        if (is_string($throttle) && $throttle !== '') {
            $middleware[] = "throttle:{$throttle}";
        }

        if (! empty($middleware)) {
            $group->middleware($middleware);
        }

        $redirect = null;

        $group->group(function () use ($controller, $loginRoute, &$redirect): void {
            $redirect = Route::get('redirect', [$controller, 'redirect'])->name($loginRoute);
            Route::get('callback', [$controller, 'callback'])->name('uzair.callback');
            Route::post('logout', [$controller, 'logout'])->name('uzair.logout');
            Route::post('logout-device/{token}', [$controller, 'logoutDevice'])
                ->whereNumber('token')
                ->name('uzair.logoutDevice');
        });

        if ($redirect instanceof RegisteredRoute) {
            self::reportIfTheNameIsTakenElsewhere($redirect, $loginRoute, $controller);
        }
    }

    /**
     * Register the endpoints a mobile client signs in and out through.
     *
     * Call from `routes/api.php`: the client has no session or CSRF token and
     * authenticates with the Sanctum token `token` issues. The client runs the
     * PKCE authorization itself and posts the code here; the exchange uses the
     * client secret, so the refresh token stays on the server.
     *
     * Throttling and options are the same as for `routes()`.
     *
     * @param  array{prefix?: string, throttle?: string|null, controller?: class-string, middleware?: array<array-key, mixed>|string}  $options
     */
    public static function apiRoutes(array $options = []): void
    {
        $prefix = $options['prefix'] ?? config('uzairports.api.prefix', 'auth');
        $throttle = array_key_exists('throttle', $options) ? $options['throttle'] : 'uzairid';
        $controller = $options['controller'] ?? UzairApiAuthController::class;

        $group = Route::prefix(is_string($prefix) ? $prefix : 'auth');

        $middleware = (array) ($options['middleware'] ?? []);

        if (is_string($throttle) && $throttle !== '') {
            $middleware[] = "throttle:{$throttle}";
        }

        if (! empty($middleware)) {
            $group->middleware($middleware);
        }

        $group->group(function () use ($controller): void {
            Route::post('token', [$controller, 'token'])->name('uzair.api.token');
            Route::post('logout', [$controller, 'logout'])->name('uzair.api.logout');
            Route::post('logout-device/{token}', [$controller, 'logoutDevice'])
                ->whereNumber('token')
                ->name('uzair.api.logoutDevice');
        });
    }

    /**
     * Warn if another route carries the sign-in route's name.
     *
     * Laravel silently keeps whichever same-named route registered last, so
     * either guests are sent into SSO instead of the app's form, or
     * `loginUrl()` loops back to that form. The check runs in `app()->booted()`
     * because route file order is outside this package's control, and asks
     * whether any other route carries the name, not which one won, so both
     * directions are caught.
     *
     * This package's own redirect routes (e.g. under two prefixes) are not
     * counted. Nothing is thrown; which route keeps the name is the app's call.
     *
     * @param  class-string  $controller
     */
    private static function reportIfTheNameIsTakenElsewhere(RegisteredRoute $redirect, string $loginRoute, string $controller): void
    {
        app()->booted(function () use ($redirect, $loginRoute, $controller): void {
            /** @var list<string> $contested */
            $contested = [];

            foreach (Route::getRoutes()->getRoutes() as $route) {
                if ($route->getName() === $loginRoute && ! self::isTheSignInRedirect($route, $controller)) {
                    $contested[] = $route->uri();
                }
            }

            if ($contested === []) {
                return;
            }

            Log::warning("The route name [{$loginRoute}] is carried by more than one route, and Laravel keeps only whichever was registered last — so either a guest is sent into SSO instead of the application's sign-in form, or [uzairports.login_route] and Uzair::loginUrl() lead back to that form. Point the setting at a name of its own, or take the name off the other route.", [
                'sign_in_uri' => $redirect->uri(),
                'also_named' => $contested,
            ]);
        });
    }

    /**
     * Whether a route is a sign-in redirect this package registered.
     *
     * @param  class-string  $controller
     */
    private static function isTheSignInRedirect(RegisteredRoute $route, string $controller): bool
    {
        $action = $route->getAction('controller');

        return is_string($action) && $action === $controller.'@redirect';
    }
}
