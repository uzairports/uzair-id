<?php

namespace Uzairports\Uzairid;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Route;
use Laravel\Socialite\Two\User as SocialiteUser;
use Uzairports\Uzairid\Http\Controllers\UzairAuthController;

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
     * Register the SSO endpoints.
     *
     * Call this from the application's `routes/web.php`, so the routes inherit
     * the session and CSRF middleware the OAuth flow needs. The name of the
     * redirect route is read from `uzairports.login_route`, which is also where
     * the refresh middleware sends a session it can no longer renew — naming
     * them apart would send the user to a page that cannot sign them in.
     *
     * The routes sit behind the `uzairid` limiter, which reads its budget from
     * `uzairports.routes.throttle` and counts it per browser. Pass `throttle`
     * to name a different limiter, or an `attempts,minutes` pair to be counted
     * by Laravel's default key instead; pass null to register without a limit.
     *
     * There is no "sign-out everywhere" endpoint. Ending an account's logins
     * means surrendering each grant to the identity provider in turn, and one
     * request cannot answer for an unbounded number of them: an account signed
     * in on a dozen devices would spend a dozen revocation timeouts before the
     * browser heard anything back. `logout-device` ends them one at a time,
     * off the list of devices the account can already see, and each request
     * costs one login's worth of waiting.
     *
     * `logout-device` names a login by its row id, which is always an integer,
     * so the parameter is constrained to digits. Without that a request for
     * `/logout-device/abc` would reach the query and be compared against a
     * `bigint` column — a 404 on SQLite and MySQL, but a type error, and so a
     * 500, on PostgreSQL.
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

        $group->group(function () use ($controller, $loginRoute): void {
            Route::get('redirect', [$controller, 'redirect'])->name($loginRoute);
            Route::get('callback', [$controller, 'callback'])->name('uzair.callback');
            Route::post('logout', [$controller, 'logout'])->name('uzair.logout');
            Route::post('logout-device/{token}', [$controller, 'logoutDevice'])
                ->whereNumber('token')
                ->name('uzair.logoutDevice');
        });
    }
}
