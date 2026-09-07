<?php

namespace Uzairports\Uzairid\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Symfony\Component\HttpFoundation\Response;
use Uzairports\Uzairid\Actions\RefreshAccessToken;
use Uzairports\Uzairid\Models\OauthToken;

class EnsureAccessTokenIsFresh
{
    public function __construct(private readonly RefreshAccessToken $refreshAccessToken) {}

    /**
     * Refresh the UzAirports access token before it expires.
     *
     * When the refresh token is no longer accepted the session is dropped so
     * the user is sent back through the SSO flow instead of carrying a dead token.
     *
     * @param  Closure(Request): Response  $next
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

        if ($token === null || ! $token->expiresWithin($this->leewayInSeconds())) {
            return $next($request);
        }

        if (($this->refreshAccessToken)($token)) {
            return $next($request);
        }

        $token->delete();

        Auth::logout();
        $request->session()->invalidate();
        $request->session()->regenerateToken();

        return redirect()->route('login');
    }

    /**
     * How long before the actual expiry the token should be renewed.
     */
    private function leewayInSeconds(): int
    {
        return (int) config('services.uzairports.refresh_leeway', 60);
    }
}
