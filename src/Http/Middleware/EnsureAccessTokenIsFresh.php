<?php

namespace Uzairports\Uzairid\Http\Middleware;

use Closure;
use Illuminate\Auth\AuthenticationException;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Route;
use Symfony\Component\HttpFoundation\Response;
use Uzairports\Uzairid\Actions\RefreshAccessToken;
use Uzairports\Uzairid\Models\OauthToken;

class EnsureAccessTokenIsFresh
{
    public function __construct(private RefreshAccessToken $refreshAccessToken) {}

    /**
     * Refresh this session's UzAirports access token before it expires and
     * refuse a session whose login has been ended.
     *
     * A login belongs to one browser session, so the pair looks up the token:
     * another device's row is none of this request's business. When the
     * refresh token is no longer accepted, or the login was ended elsewhere —
     * signed out on this device from another, or dropped by
     * `uzairports.single_session` when the account signed in again — the
     * session is dropped and an authentication failure raised, so the
     * request is answered the way the application answers any other
     * unauthenticated one: a redirect back through SSO for a browser, a 401 for
     * an API client.
     *
     * @param  Closure(Request): Response  $next
     *
     * @throws AuthenticationException when the session can no longer be renewed
     */
    public function handle(Request $request, Closure $next): Response
    {
        $user = $request->user();

        if ($user === null) {
            return $next($request);
        }

        $token = $this->tokenFor($request, $user);

        if ($token === null) {
            if (! $this->isUzairUser($user)) {
                return $next($request);
            }

            $this->endSession($request);

            throw new AuthenticationException(
                __('uzairid::messages.session_ended'),
                [],
                $this->loginUrl(),
            );
        }

        $leeway = $this->leewayInSeconds();

        if (! $token->expiresWithin($leeway)) {
            $token->keepAlive();

            return $next($request);
        }

        if (($this->refreshAccessToken)($token, $leeway)) {
            return $next($request);
        }

        // A request carrying no session is not the browser that made this login
        // — the row it was matched with belongs to whichever device signed in
        // last, and dropping it would sign that device out over a call it never
        // made. The request is still refused, because the token it would have
        // used cannot be renewed, but the login is left where it stands.
        if ($request->hasSession()) {
            $token->delete();
        }

        $this->endSession($request);

        throw new AuthenticationException(
            __('uzairid::messages.session_expired'),
            [],
            $this->loginUrl(),
        );
    }

    /**
     * The login this request is running on.
     *
     * A request without a session — an API client, a console command — names no
     * browser, so there is nothing to match on, and the account's most recent
     * login is the best that can be said. It is a guess, and it is somebody
     * else's row: the caller may read a token through it, but nothing it does
     * may end that login. `handle()` keeps to that.
     *
     * The session is read off the request this middleware was handed rather
     * than off the global one: they are the same object in an ordinary HTTP
     * request, but nothing guarantees it, and the request in hand is the one
     * whose session this decision is about.
     *
     * What is found is handed to a user model carrying `HasUzairToken`, so that
     * anything downstream asking the user for its login — a controller, a view —
     * reads what was looked up here instead of repeating the query.
     */
    private function tokenFor(Request $request, Authenticatable $user): ?OauthToken
    {
        $tokens = OauthToken::query()->where('user_id', $user->getAuthIdentifier());

        if (! $request->hasSession()) {
            return $tokens->latest('id')->first();
        }

        $sessionId = $request->session()->getId();

        $token = $tokens->where('session_id', $sessionId)->first();

        if (method_exists($user, 'rememberCurrentToken')) {
            $user->rememberCurrentToken($token, $sessionId);
        }

        return $token;
    }

    private function isUzairUser(Authenticatable $user): bool
    {
        return $user instanceof Model && filled($user->getAttribute('uzair_id'));
    }

    /**
     * Leave nothing of the current session behind.
     */
    private function endSession(Request $request): void
    {
        Auth::logout();

        if ($request->hasSession()) {
            $request->session()->invalidate();
            $request->session()->regenerateToken();
        }
    }

    /**
     * How long before the actual expiry the token should be renewed.
     *
     * A leeway that is not a number is a misconfiguration, and casting one
     * would read as no leeway at all — leaving every token to expire in the
     * middle of the request that was using it. The default stands instead.
     */
    private function leewayInSeconds(): int
    {
        $leeway = config('uzairports.refresh_leeway', 60);

        return is_numeric($leeway) ? (int) $leeway : 60;
    }

    /**
     * Where a browser is sent to authenticate again.
     *
     * A missing route would raise a `RouteNotFoundException` here — a 500 in
     * place of the redirect, at the one moment the user most needs to be sent
     * back through SSO. An unresolvable name therefore falls back to the site
     * root, and the caller is left to notice the misconfiguration in the log.
     */
    private function loginUrl(): string
    {
        $route = config('uzairports.login_route', 'login');

        if (! is_string($route) || $route === '') {
            $route = 'login';
        }

        if (Route::has($route)) {
            return route($route);
        }

        Log::warning("The route [{$route}] configured as [uzairports.login_route] is not registered.");

        return url('/');
    }
}
