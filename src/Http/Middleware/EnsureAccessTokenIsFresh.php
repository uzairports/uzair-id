<?php

namespace Uzairports\Uzairid\Http\Middleware;

use Closure;
use Illuminate\Auth\AuthenticationException;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\Factory as AuthFactory;
use Illuminate\Contracts\Auth\StatefulGuard;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;
use Throwable;
use Uzairports\Uzairid\Actions\EndSessions;
use Uzairports\Uzairid\Actions\EnsureTokenStorageMatchesProvider;
use Uzairports\Uzairid\Actions\RefreshAccessToken;
use Uzairports\Uzairid\Events\UzairLoggedOut;
use Uzairports\Uzairid\Models\OauthToken;
use Uzairports\Uzairid\Uzair;

class EnsureAccessTokenIsFresh
{
    public function __construct(
        private readonly RefreshAccessToken $refreshAccessToken,
        private readonly EndSessions $endSessions,
    ) {}

    /**
     * Refresh the caller's UzAirports access token before it expires and refuse
     * a caller whose login has been ended or can no longer be renewed. A refusal
     * ends the session and raises an authentication failure, so the application
     * answers it like any other unauthenticated request.
     *
     * Callers holding no login are let through when the account was never linked
     * (no `uzair_id`) or the application marked the session/request as local
     * (`Uzair::markSessionAsLocal()`, `treatRequestsAsLocalWhen()`,
     * `markRequestAsLocal()`). The mark is checked only after the row lookup, so
     * a caller that holds a login still has it renewed.
     *
     * The guard comes from the route (`uzair.token:admin`), then
     * `uzairports.guard`, then the application default; it must match the guard
     * that authenticated the route.
     *
     * @param  Closure(Request): Response  $next
     *
     * @throws AuthenticationException when the session can no longer be renewed
     * @throws Throwable
     */
    public function handle(Request $request, Closure $next, ?string $guard = null): Response
    {
        $guard ??= Uzair::guard();

        $user = $request->user($guard);

        if ($user === null) {
            return $next($request);
        }

        app(EnsureTokenStorageMatchesProvider::class)->forUser($user);

        $leeway = $this->leewayInSeconds();
        $accessTokenId = Uzair::accessTokenId($user);

        // The cache is keyed by session; a Sanctum-token caller must not pass on
        // a session's cached login.
        if ($accessTokenId === null && $this->alreadyResolvedAsFresh($request, $user, $leeway)) {
            return $next($request);
        }

        $token = $this->tokenFor($request, $user, $accessTokenId);

        if ($token === null) {
            if (! $this->isUzairUser($user) || Uzair::requestIsLocal($request)) {
                return $next($request);
            }

            $this->endSession($request, $user, $guard);

            throw new AuthenticationException(
                __('uzairid::messages.session_ended'),
                [],
                Uzair::loginUrl(),
            );
        }

        if (! $token->expiresWithin($leeway)) {
            $token->keepAlive();
            $this->rememberResolved($request, $token, $accessTokenId);

            return $next($request);
        }

        if (($this->refreshAccessToken)($token, $leeway)) {
            $this->rememberResolved($request, $token, $accessTokenId);

            return $next($request);
        }

        // The row is always this caller's own, so an unrenewable login ends
        // with the refusal. It goes through `end()`, not a bare delete: the
        // access token may still be live, and `end()` surrenders both grants
        // and skips a row another request already deleted.
        $this->endSessions->end($token);

        $this->endSession($request, $user, $guard);

        throw new AuthenticationException(
            __('uzairid::messages.session_expired'),
            [],
            Uzair::loginUrl(),
        );
    }

    /**
     * The login this request is running on, looked up in order: by Sanctum
     * token (see `OauthToken::scopeHeldBy()`), by the session id of the request
     * in hand, or, for a request with neither, the most recent login that names
     * no session. A sessionless request never reads or renews a browser's login.
     *
     * When nothing is found, a regenerated session is followed to its previous
     * id (`Uzair::followRegeneratedSession()`) and looked up again.
     *
     * The result is handed to a `HasUzairToken` user for every kind of request,
     * so downstream code reads it without repeating the query.
     */
    private function tokenFor(Request $request, Authenticatable $user, int|string|null $accessTokenId): ?OauthToken
    {
        $sessionId = $request->hasSession() ? $request->session()->getId() : null;

        $token = $this->lookUpToken($user, $sessionId, $accessTokenId);

        $followsTheSession = $sessionId !== null && $accessTokenId === null;

        if ($token === null && $followsTheSession && Uzair::followRegeneratedSession($request, $user->getAuthIdentifier())) {
            $token = $this->lookUpToken($user, $sessionId, null);
        }

        if ($token !== null && $followsTheSession) {
            Uzair::rememberSession($request);
        }

        if (method_exists($user, 'rememberCurrentToken')) {
            $user->rememberCurrentToken($token, $sessionId, $accessTokenId);
        }

        return $token;
    }

    /**
     * The account's login for a Sanctum token, a session id, or for naming neither.
     */
    private function lookUpToken(Authenticatable $user, ?string $sessionId, int|string|null $accessTokenId): ?OauthToken
    {
        return OauthToken::query()
            ->where('user_id', $user->getAuthIdentifier())
            ->heldBy($sessionId, $accessTokenId)
            ->first();
    }

    /**
     * Whether a login cached for this session within `uzairports.login_cache_ttl`
     * (zero by default) lets the request through without reading the row.
     *
     * A session id is not proof of an account, so the cached account is compared
     * first and a mismatch falls through to the row. An unknown expiry is never
     * treated as fresh.
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

        // A key that is neither int nor string cannot be compared; the row answers.
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
    private function rememberResolved(Request $request, OauthToken $token, int|string|null $accessTokenId): void
    {
        if ($accessTokenId === null && $request->hasSession()) {
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
     * The cached login is forgotten before invalidation, which regenerates the
     * session id the entry is keyed by; `forgetLogin()` does not throw, so the
     * session is always invalidated. Only stateful guards are logged out, since
     * token guards have no `logout()`.
     *
     * `UzairLoggedOut` is dispatched here too, so listeners also hear about
     * logins ended elsewhere or no longer renewable.
     */
    private function endSession(Request $request, Authenticatable $user, ?string $guard): void
    {
        // The contract, not the facade: the guard may not be stateful.
        $authenticator = app(AuthFactory::class)->guard($guard);

        if ($authenticator instanceof StatefulGuard) {
            $authenticator->logout();
        }

        if ($request->hasSession()) {
            OauthToken::forgetLogin($request->session()->getId());

            $request->session()->invalidate();
            $request->session()->regenerateToken();
        }

        UzairLoggedOut::dispatch($user instanceof Model ? $user : null);
    }

    /**
     * How long before the actual expiry the token should be renewed.
     *
     * A non-numeric value falls back to the default rather than casting to zero.
     */
    private function leewayInSeconds(): int
    {
        $leeway = config('uzairports.refresh_leeway', 60);

        return is_numeric($leeway) ? (int) $leeway : 60;
    }
}
