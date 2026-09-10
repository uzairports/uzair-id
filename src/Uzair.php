<?php

namespace Uzairports\Uzairid;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\Request;
use Illuminate\Routing\Route as RegisteredRoute;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Route;
use Laravel\Socialite\Two\User as SocialiteUser;
use Uzairports\Uzairid\Actions\RefreshAccessToken;
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
     * Drop the static state that must not outlive the request that filled it.
     *
     * Under PHP-FPM the process ends with the response and takes it along;
     * under a long-lived worker — Octane, FrankenPHP — the same worker serves
     * the next request with everything the last one left behind. Three fields
     * are affected:
     *
     * - `OauthToken::$pruner`, an action resolved out of the container, which
     *   after a rebinding is holding dependencies the application has replaced;
     * - The three registers behind the once-per-process warnings about the
     *   login cache, the lock store, and an unregistered login route, which
     *   otherwise stays marked for the life of the worker — so a setting
     *   misconfigured after a deployment is reported once in days rather than once
     *   per boot.
     *
     * The user resolver is deliberately not among them. It is registered once
     * while the application boots, the way a route or a binding is, and a
     * worker that dropped it would serve every later request without it.
     *
     * `UzairServiceProvider` calls this on Octane's terminating events. An
     * application on another long-lived runtime should call it wherever that
     * runtime says a request is over.
     */
    public static function flushState(): void
    {
        OauthToken::flushPruner();
        OauthToken::flushLoginCacheWarnings();
        RefreshAccessToken::flushLockStoreWarnings();
        self::flushLoginRouteWarnings();
    }

    /**
     * Where a browser is sent to sign in through UzAirports ID.
     *
     * The `redirect` endpoint is named by `uzairports.login_route`, and that is
     * deliberate — it is the sign-in page, and both `redirectGuestsTo()` and
     * Laravel's own `Authenticate` look for `login`. What it leaves an
     * application without is a name it can write down: one that keeps its own
     * `login` route points the setting somewhere else, and then every template
     * linking to SSO has to know what it was pointed at. `route('uzair.redirect')`
     * is not that name and never will be, because Laravel gives a route one
     * name — `Route::name()` appends rather than aliases — and a second route on
     * the same URI to carry an alias is a trick that reads as a mistake later.
     *
     * So the name is resolved here instead, and a template asks for the URL
     * rather than for a name. A setting naming no registered route answers with
     * the site root: a broken sign-in link is worth less than the 500 that
     * `route()` would raise at the one moment somebody is trying to sign in.
     *
     * This is the only place the setting is turned into a URL. `uzair.token`
     * resolved it a second time for the redirect it hands an
     * `AuthenticationException`, which is the same three lines and the same
     * fallback — and a second copy of a decision is a second place for it to
     * drift.
     *
     * A name that resolves to nothing is worth a line in the log, since what
     * follows is a user quietly landing on the site root instead of signing in.
     * It is said once per process: the setting is misconfigured for as long as
     * it is misconfigured, and a template calling this on every page would
     * otherwise write the line on every request.
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
     * Let the warning be said again, for a suite that asserts on it.
     *
     * Reached between requests on a long-lived runtime through `flushState()`,
     * which is where the reason is written down.
     */
    public static function flushLoginRouteWarnings(): void
    {
        self::$reportedAboutTheLoginRoute = [];
    }

    /**
     * Where the session notes the id the login it holds is filed under.
     */
    private const string SESSION_KEY = 'uzairid.session';

    /**
     * Where the session notes that this application authenticated it itself.
     */
    private const string LOCAL_KEY = 'uzairid.local';

    /**
     * Note the session id this browser's login is filed under.
     *
     * The note is what `followRegeneratedSession()` compares against, and it
     * lives in the session payload — the application's own store, which the
     * browser holds a key to and never writes. Rewritten only when the id has
     * changed, so an unchanged session is not marked dirty by being read.
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
     * Take the login with the browser when its session is given a new id.
     *
     * `regenerate()` keeps the payload and changes the id, so the note written
     * by `rememberSession()` still holds the id the login was filed under while
     * the session answers to a new one. That difference is the whole signal:
     * the browser is the same browser, and the row is moved to the id it
     * carries now. Laravel fires nothing on a regeneration, and the alternative
     * — a login found by nothing at all — signs a signed-in user out.
     *
     * The account is passed in, and the move is scoped to it because the note
     * says which session this is and not whose login it is. `getAuthIdentifier()`
     * promises nothing about what it hands back, and a key that is neither an
     * integer nor a string names no account to scope by, so nothing is moved
     * for it.
     *
     * The note is brought up to date whatever the move did. A session whose
     * login has genuinely gone must not spend a statement looking for it again
     * on every request for as long as the browser keeps it.
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
     * `uzair.token` refuses a session holding no login when the account carries
     * a `uzair_id`, and it is right to: the login was ended somewhere, and what
     * is left is a session with nothing behind it. An account that has ever
     * signed in through SSO carries that column for good, though, so the same
     * refusal met a hybrid application's own password sign-in — a user who used
     * SSO once could never be signed in by the application again, on any route
     * carrying the middleware.
     *
     * The mark says the difference the column cannot: this session's
     * authentication does not come from UzAirports ID and must not be measured
     * against a login row. Call it from wherever the application signs a
     * browser in itself, after it has done so — `Auth::attempt()` migrates the
     * session, and a mark written before that is written into the session that
     * is about to be replaced.
     *
     * It is a statement about how this browser was authenticated, so only the
     * application making that statement may write it, and only into a session
     * it has just authenticated. It ends with the session: signing out
     * invalidates it, and signing in through SSO takes it off.
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
     * Stop a session counting as one the application authenticated itself.
     *
     * The callback calls this: a browser that signs in through SSO holds a
     * login row from that moment, and a mark left over from a password sign-in
     * in the same session would go on exempting it from the one check that
     * notices the login being ended.
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
     * Say so if something else ends up answering to the sign-in route's name.
     *
     * Two routes may carry one name, and Laravel says nothing about it: the name
     * list simply keeps whichever was registered last. An application with its
     * own `login` — Breeze, Jetstream, Fortify, a handwritten form — and
     * `login_route` left at the default therefore has one of two things happen
     * silently, and both look like a bug somewhere else entirely. If this
     * package wins, a guest opening the application's sign-in page is thrown
     * straight into SSO and never sees the form. If the application wins,
     * `Uzair::loginUrl()` and `redirectGuestsTo()` resolve to that form — so the
     * "sign in through UzAirports ID" button on it leads back to the page it is
     * on, which is a loop nobody can read their way out of.
     *
     * The check is deferred to the end of boot because route files run in an
     * order this package does not control: asked at registration, it would only
     * catch the applications that registered theirs first.
     *
     * What is asked is whether anything else carries the name at all, not which
     * of them the name list happens to hold. Either way round is a problem, and
     * only one of them is visible from the name list: whoever registered last
     * holds it, so asking "is it mine?" would report the application's route
     * winning and say nothing when this package's route wins — which is the
     * half that throws a guest into SSO instead of showing them the form.
     *
     * Routes registered by this package are not counted against each other. An
     * application registering the endpoints twice, under two prefixes is doing
     * nothing wrong and must hear nothing.
     *
     * Nothing is refused over it. Which route should hold the name is the
     * application's to decide — the note on `login_route` gives both ways of
     * deciding — and a package that started throwing here would break the
     * deployments that have already chosen.
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
     * Whether a route is a sign-in redirect, this package registered.
     *
     * @param  class-string  $controller
     */
    private static function isTheSignInRedirect(RegisteredRoute $route, string $controller): bool
    {
        $action = $route->getAction('controller');

        return is_string($action) && $action === $controller.'@redirect';
    }
}
