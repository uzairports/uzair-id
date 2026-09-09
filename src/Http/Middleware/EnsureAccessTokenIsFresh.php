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
use Uzairports\Uzairid\Actions\EndSessions;
use Uzairports\Uzairid\Actions\RefreshAccessToken;
use Uzairports\Uzairid\Models\OauthToken;

class EnsureAccessTokenIsFresh
{
    public function __construct(
        private RefreshAccessToken $refreshAccessToken,
        private EndSessions $endSessions,
    ) {}

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

        $leeway = $this->leewayInSeconds();

        if ($this->alreadyResolvedAsFresh($request, $user, $leeway)) {
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

        if (! $token->expiresWithin($leeway)) {
            $token->keepAlive();
            $this->rememberResolved($request, $token);

            return $next($request);
        }

        if (($this->refreshAccessToken)($token, $leeway)) {
            $this->rememberResolved($request, $token);

            return $next($request);
        }

        // The row is this caller's own either way — the session that made it,
        // or a login that names no session for a request that names none
        // either — so a login that can no longer be renewed goes with the
        // refusal. It used to be somebody else's, and dropping it would have
        // signed that device out over a call it never made; `tokenFor()` no
        // longer hands out a browser's login to a request without a session.
        //
        // It goes the way every other ending in this package goes, rather than
        // by deleting the row here. What the exchange was refused is the
        // refresh token; the access token beside it is good for up to the
        // leeway this renewal was started within, and dropping the row alone
        // left that much of a live grant behind with nothing left pointing at
        // it to ever surrender it. `end()` hands both back, and a row another
        // request has already deleted is found to be gone rather than revoked
        // on a stale snapshot.
        $this->endSessions->end($token);

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
     * browser, so it is matched against the logins that name no browser either:
     * `session_id` is nullable precisely because a token can be issued outside
     * a session, and such a row is the caller's own.
     *
     * It used to be handed the account's most recent login instead, which is
     * whichever browser signed in last — somebody else's row. Reading a token
     * through it was the least of it: the request went on to keep that login
     * alive on every call, so an abandoned browser's row never aged into
     * `prunable()` and the grant behind it was never surrendered, and it spent
     * that browser's rotating refresh token to renew a token the caller has no
     * supported way to read — `HasUzairToken::currentToken()` answers null
     * without a session. A request that names no browser now neither reads nor
     * writes a login belonging to one.
     *
     * The unique pair does not collapse several null session ids, so the most
     * recent of them is taken.
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
            return $tokens->whereNull('session_id')->latest('id')->first();
        }

        $sessionId = $request->session()->getId();

        $token = $tokens->where('session_id', $sessionId)->first();

        if (method_exists($user, 'rememberCurrentToken')) {
            $user->rememberCurrentToken($token, $sessionId);
        }

        return $token;
    }

    /**
     * Whether this request may go through on a login already resolved for it.
     *
     * Every request through this middleware reads `oauth_tokens` to ask two
     * questions of one row — is the login still there, and is its token still
     * good — and for a browser clicking around an application the answer is the
     * same on almost all of them. `uzairports.login_cache_ttl` lets the answer
     * stand for a few seconds so those requests cost nothing, and it is zero by
     * default, which is the behaviour of reading the row every time.
     *
     * What the entry cannot be trusted for is who it belongs to. A session id
     * is not proof of an account — the browser holding it now may not be the
     * one it was written for — so the account is compared before the entry is
     * used, and a mismatch falls through to the row.
     *
     * An unknown expiry is not freshness: `expiresWithin()` treats it as
     * expired, so a login stored without one is renewed rather than let past.
     */
    private function alreadyResolvedAsFresh(Request $request, Authenticatable $user, int $leeway): bool
    {
        if (! $request->hasSession()) {
            return false;
        }

        $resolved = OauthToken::cachedLogin($request->session()->getId());

        if ($resolved === null || $resolved['expires_at'] === null) {
            return false;
        }

        // `getAuthIdentifier()` promises nothing about what it hands back, and
        // a key that is neither an integer nor a string names no account to
        // compare against. The row answers instead.
        $key = $user->getAuthIdentifier();

        if ((! is_int($key) && ! is_string($key)) || $resolved['user'] !== (string) $key) {
            return false;
        }

        return $resolved['expires_at'] > now()->addSeconds($leeway)->getTimestamp();
    }

    /**
     * Let the login just resolved answer for the next few requests.
     */
    private function rememberResolved(Request $request, OauthToken $token): void
    {
        if ($request->hasSession()) {
            $token->cacheLogin($request->session()->getId());
        }
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
            OauthToken::forgetLogin($request->session()->getId());

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
