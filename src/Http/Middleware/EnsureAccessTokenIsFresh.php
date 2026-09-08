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
     * Refresh this session's UzAirports access token before it expires, and
     * refuse a session whose login has been ended.
     *
     * A login belongs to one browser session, so the token is looked up by the
     * pair: another device's row is none of this request's business. When the
     * refresh token is no longer accepted, or the login was ended elsewhere —
     * signed out on this device from another, or through "sign out everywhere"
     * — the session is dropped and an authentication failure raised, so the
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
            return $next($request);
        }

        if (($this->refreshAccessToken)($token, $leeway)) {
            return $next($request);
        }

        $token->delete();

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
     * browser, so there is nothing to match on and the account's most recent
     * login is the best that can be said.
     */
    private function tokenFor(Request $request, Authenticatable $user): ?OauthToken
    {
        $tokens = OauthToken::query()->where('user_id', $user->getAuthIdentifier());

        if (! $request->hasSession()) {
            return $tokens->latest('id')->first();
        }

        return $tokens->where('session_id', $request->session()->getId())->first();
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
     */
    private function leewayInSeconds(): int
    {
        return (int) config('uzairports.refresh_leeway', 60);
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
