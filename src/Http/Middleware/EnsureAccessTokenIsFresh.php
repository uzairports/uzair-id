<?php

namespace Uzairports\Uzairid\Http\Middleware;

use Closure;
use Illuminate\Auth\AuthenticationException;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Symfony\Component\HttpFoundation\Response;
use Throwable;
use Uzairports\Uzairid\Actions\EndSessions;
use Uzairports\Uzairid\Actions\RefreshAccessToken;
use Uzairports\Uzairid\Models\OauthToken;
use Uzairports\Uzairid\Uzair;

class EnsureAccessTokenIsFresh
{
    public function __construct(
        private readonly RefreshAccessToken $refreshAccessToken,
        private readonly EndSessions $endSessions,
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
     * Two sessions holding no login are let through rather than refused. One
     * belongs to an account this package never linked, which is a local account
     * living as it always did. The other was authenticated by the application
     * itself and says so — `Uzair::markSessionAsLocal()` — which is the only
     * thing that tells a hybrid application's password sign-in apart from a
     * login that was ended, since an account that ever signed in through SSO
     * carries `uzair_id` for good. The mark is asked for only once no login was
     * found, so a session that holds one still has its token renewed on the
     * ordinary path.
     *
     * @param  Closure(Request): Response  $next
     *
     * @throws AuthenticationException when the session can no longer be renewed
     * @throws Throwable
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
            if (! $this->isUzairUser($user) || Uzair::sessionIsLocal($request)) {
                return $next($request);
            }

            $this->endSession($request);

            throw new AuthenticationException(
                __('uzairid::messages.session_ended'),
                [],
                Uzair::loginUrl(),
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
            Uzair::loginUrl(),
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
     * that browser's rotating refresh token to renew a token the caller had no
     * supported way to read. A request that names no browser now neither reads
     * nor writes a login belonging to one.
     *
     * The unique pair does not collapse several null session ids, so the most
     * recent of them is taken.
     *
     * The session is read off the request this middleware was handed rather
     * than off the global one: they are the same object in an ordinary HTTP
     * request, but nothing guarantees it, and the request in hand is the one
     * whose session this decision is about.
     *
     * A browser whose session was given a new id is still the same browser.
     * Its login is moved to that id rather than lost with the old one — see
     * `Uzair::followRegeneratedSession()`, which is asked only once the lookup
     * has come back with nothing. Finding a login is the common answer and the
     * inexpensive one; a session that carries no note of an earlier id answers
     * without a statement completely.
     *
     * What is found is handed to a user model carrying `HasUzairToken`,
     * whichever kind of request it was, so that anything downstream asking the
     * user for its login — a controller, a view — reads what was looked up here
     * instead of repeating the query. The sessionless branch used to skip that
     * hand-off, which left an API client's controller unable to reach a token
     * this method had just resolved for it.
     */
    private function tokenFor(Request $request, Authenticatable $user): ?OauthToken
    {
        $sessionId = $request->hasSession() ? $request->session()->getId() : null;

        $token = $this->lookUpToken($user, $sessionId);

        if ($token === null && $sessionId !== null && Uzair::followRegeneratedSession($request, $user->getAuthIdentifier())) {
            $token = $this->lookUpToken($user, $sessionId);
        }

        if ($token !== null && $sessionId !== null) {
            Uzair::rememberSession($request);
        }

        if (method_exists($user, 'rememberCurrentToken')) {
            $user->rememberCurrentToken($token, $sessionId);
        }

        return $token;
    }

    /**
     * The account's login for a session id, or for naming none.
     */
    private function lookUpToken(Authenticatable $user, ?string $sessionId): ?OauthToken
    {
        $tokens = OauthToken::query()->where('user_id', $user->getAuthIdentifier());

        return $sessionId === null
            ? $tokens->whereNull('session_id')->latest('id')->first()
            : $tokens->where('session_id', $sessionId)->first();
    }

    /**
     * Whether this request may go through on a login already resolved for it.
     *
     * Every request through this middleware reads `oauth_tokens` to ask two
     * questions of one row — is the login still there, and is its token still
     * good — and for a browser clicking around an application, the answer is the
     * same on almost all of them. `uzairports.login_cache_ttl` lets the answer
     * stand for a few seconds, so those requests cost nothing, and it is zero by
     * default, which is the behavior of reading the row every time.
     *
     * What the entry cannot be trusted for is who it belongs to. A session id
     * is not proof of an account — the browser holding it now may not be the
     * one it was written for — so the account is compared before the entry is
     * used, and a mismatch falls through to the row.
     *
     * Unknown expiry is not freshness: `expiresWithin()` treats it as
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
     *
     * @throws Throwable
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
     *
     * The cached login is forgotten before the session is invalidated, not
     * after: invalidating regenerates the id, and the entry is keyed by the id
     * the browser was actually holding. `forgetLogin()` reports a store that
     * will not answer rather than raising it, so the invalidation below happens
     * whatever the cache does — a session left standing here is a browser still
     * carrying a session this request has just decided to refuse.
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
}
