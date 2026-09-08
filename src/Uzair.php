<?php

namespace Uzairports\Uzairid;

use Illuminate\Support\Facades\Route;
use Uzairports\Uzairid\Http\Controllers\UzairAuthController;

class Uzair
{
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
     * @param  array{prefix?: string, throttle?: string|null, controller?: class-string}  $options
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

        if (is_string($throttle) && $throttle !== '') {
            $group->middleware("throttle:{$throttle}");
        }

        $group->group(function () use ($controller, $loginRoute): void {
            Route::get('redirect', [$controller, 'redirect'])->name($loginRoute);
            Route::get('callback', [$controller, 'callback'])->name('uzair.callback');
            Route::post('logout', [$controller, 'logout'])->name('uzair.logout');
            Route::post('logout-all', [$controller, 'logoutAll'])->name('uzair.logoutAll');
        });
    }
}
