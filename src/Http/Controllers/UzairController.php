<?php

namespace Uzairports\Uzairid\Http\Controllers;

use Illuminate\Auth\AuthenticationException;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\Factory as AuthFactory;
use Illuminate\Contracts\Auth\StatefulGuard;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Route;
use Laravel\Socialite\Two\User as SocialiteUser;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;
use Throwable;
use Uzairports\Uzairid\Actions\EndSessions;
use Uzairports\Uzairid\Actions\EnsureTokenStorageMatchesProvider;
use Uzairports\Uzairid\Events\UzairLoggedOut;
use Uzairports\Uzairid\Models\OauthToken;
use Uzairports\Uzairid\Uzair;

/**
 * The sign-out endpoints shared by the browser and the mobile controllers.
 *
 * A caller's own login is the one filed under the Sanctum token it
 * authenticated with, or else under its browser session — see
 * `OauthToken::scopeHeldBy()`. Ending a login drops the row, its session or
 * Sanctum token, and surrenders its grants; an identity provider that cannot
 * be reached never keeps anybody signed in here.
 */
abstract class UzairController
{
    /**
     * Sign this device out, leaving the account's other devices alone.
     *
     * The endpoint carries no `uzair.token`, so a browser session renamed since
     * its login was recorded is followed here first; otherwise the login would
     * not be found and its grant never surrendered.
     *
     * @throws Throwable
     */
    public function logout(Request $request, EndSessions $endSessions): JsonResponse|RedirectResponse
    {
        $user = $this->authenticated();

        if ($user !== null) {
            $accessTokenId = Uzair::accessTokenId($user);

            if ($accessTokenId === null) {
                Uzair::followRegeneratedSession($request, $user->getAuthIdentifier());
            }

            $token = OauthToken::query()
                ->where('user_id', $user->getAuthIdentifier())
                ->heldBy($this->sessionId($request), $accessTokenId)
                ->first();

            if ($token !== null) {
                $endSessions->end($token);
            }

            // Signing out revokes the bearer token even when no login is filed
            // under it, such as one the application issued itself.
            if ($accessTokenId !== null) {
                $endSessions->dropAccessTokens([$accessTokenId]);
            }

            $this->signOut();

            UzairLoggedOut::dispatch($user instanceof Model ? $user : null);
        }

        return $this->finishLogout($request);
    }

    /**
     * Sign one of the account's logins out, named by its row.
     *
     * The lookup is scoped to the account, so another account's row is not
     * found (404) rather than refused, and the endpoint reveals no ids. A guest
     * is told to authenticate instead. Ending the caller's own login is handed
     * to `logout()`, so its session or Sanctum token goes with it.
     *
     * @throws AuthenticationException when nobody is signed in
     * @throws NotFoundHttpException when the account holds no such login
     * @throws Throwable
     */
    public function logoutDevice(Request $request, EndSessions $endSessions, int|string $token): JsonResponse|RedirectResponse
    {
        $user = $this->authenticated();

        if ($user === null) {
            throw new AuthenticationException(
                __('uzairid::messages.session_ended'),
                [],
                Uzair::loginUrl(),
            );
        }

        // The caller's own row is told apart by its session id, so a renamed
        // session is followed first.
        Uzair::followRegeneratedSession($request, $user->getAuthIdentifier());

        $login = OauthToken::query()
            ->where('user_id', $user->getAuthIdentifier())
            ->whereKey($token)
            ->first();

        if ($login === null) {
            throw new NotFoundHttpException;
        }

        if ($this->isTheCallersOwn($request, $user, $login)) {
            return $this->logout($request, $endSessions);
        }

        $endSessions->end($login);

        return $request->wantsJson()
            ? new JsonResponse([], 204)
            : back();
    }

    /**
     * The guard these endpoints read the account off.
     */
    protected function guardName(): ?string
    {
        return Uzair::guard();
    }

    /**
     * The account the endpoints answer for, on `guardName()`.
     */
    protected function authenticated(): ?Authenticatable
    {
        $user = app(AuthFactory::class)->guard($this->guardName())->user();

        if ($user !== null) {
            app(EnsureTokenStorageMatchesProvider::class)->forUser($user);
        }

        return $user;
    }

    /**
     * The guard, if it is one that holds a session at all.
     *
     * Asked through the contract rather than the facade: a token guard such as
     * Sanctum's implements neither `login()` nor `logout()`.
     */
    protected function sessionGuard(): ?StatefulGuard
    {
        $guard = app(AuthFactory::class)->guard($this->guardName());

        return $guard instanceof StatefulGuard ? $guard : null;
    }

    /**
     * Sign out of the guard, where it holds a session to sign out of.
     */
    protected function signOut(): void
    {
        $this->sessionGuard()?->logout();
    }

    /**
     * Hand back the grants of a sign-in that failed after the code exchange.
     *
     * Nothing was written for them, so nothing else would ever surrender them.
     * Never raises: the caller is reporting the failure that brought it here.
     */
    protected function surrenderIssuedGrants(EndSessions $endSessions, ?SocialiteUser $uzairUser): void
    {
        if ($uzairUser === null) {
            return;
        }

        try {
            $endSessions->surrenderIssued($uzairUser->token, $uzairUser->refreshToken);
        } catch (Throwable $exception) {
            Log::warning('Failed to surrender the grants of an UzAirports handshake that could not be completed.', [
                'exception_class' => $exception::class,
            ]);
        }
    }

    /**
     * The session this request belongs to, if it belongs to one at all.
     */
    protected function sessionId(Request $request): ?string
    {
        return $request->hasSession() ? $request->session()->getId() : null;
    }

    /**
     * Turn a configured destination — a route name or a path — into a URL.
     */
    protected function target(mixed $destination): string
    {
        $destination = is_string($destination) && $destination !== '' ? $destination : '/';

        return Route::has($destination) ? route($destination) : url($destination);
    }

    /**
     * Whether a login is the one this request is running on.
     */
    private function isTheCallersOwn(Request $request, Authenticatable $user, OauthToken $login): bool
    {
        $accessTokenId = Uzair::accessTokenId($user);

        if ($accessTokenId !== null) {
            return $login->personal_access_token_id !== null
                && (string) $login->personal_access_token_id === (string) $accessTokenId;
        }

        return $login->session_id !== null && $login->session_id === $this->sessionId($request);
    }

    /**
     * Leave nothing of the current session behind and answer the caller.
     */
    private function finishLogout(Request $request): JsonResponse|RedirectResponse
    {
        if ($request->hasSession()) {
            $request->session()->invalidate();
            $request->session()->regenerateToken();
        }

        return $request->wantsJson()
            ? new JsonResponse([], 204)
            : redirect()->to($this->target(config('uzairports.redirect_after_logout', '/')));
    }
}
