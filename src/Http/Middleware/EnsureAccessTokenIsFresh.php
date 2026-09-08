<?php

namespace Uzairports\Uzairid\Http\Middleware;

use Closure;
use Illuminate\Auth\AuthenticationException;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Symfony\Component\HttpFoundation\Response;
use Uzairports\Uzairid\Actions\RefreshAccessToken;
use Uzairports\Uzairid\Models\OauthToken;

class EnsureAccessTokenIsFresh
{
    public function __construct(private RefreshAccessToken $refreshAccessToken) {}

    /**
     * Refresh the UzAirports access token before it expires.
     *
     * When the refresh token is no longer accepted the session is dropped and an
     * authentication failure is raised, so the request is answered the way the
     * application answers any other unauthenticated one: a redirect back through
     * the SSO flow for a browser, a 401 for an API client.
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

        $token = OauthToken::query()
            ->where('user_id', $user->getAuthIdentifier())
            ->first();

        $leeway = $this->leewayInSeconds();

        if ($token === null || ! $token->expiresWithin($leeway)) {
            return $next($request);
        }

        if (($this->refreshAccessToken)($token, $leeway)) {
            return $next($request);
        }

        $token->delete();

        Auth::logout();

        if ($request->hasSession()) {
            $request->session()->invalidate();
            $request->session()->regenerateToken();
        }

        throw new AuthenticationException(
            'The UzAirports session has expired.',
            [],
            $this->loginUrl(),
        );
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
     */
    private function loginUrl(): string
    {
        $route = config('uzairports.login_route', 'login');

        return route(is_string($route) && $route !== '' ? $route : 'login');
    }
}
