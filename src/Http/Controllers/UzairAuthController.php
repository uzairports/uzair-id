<?php

namespace Uzairports\Uzairid\Http\Controllers;

use Carbon\CarbonInterface;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\UniqueConstraintViolationException;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Str;
use Laravel\Socialite\Facades\Socialite;
use Laravel\Socialite\Two\InvalidStateException;
use Laravel\Socialite\Two\User as SocialiteUser;
use RuntimeException;
use Symfony\Component\HttpFoundation\RedirectResponse as SymfonyRedirectResponse;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;
use Throwable;
use Uzairports\Uzairid\Actions\EndSessions;
use Uzairports\Uzairid\Actions\ResolveUserFromSocialite;
use Uzairports\Uzairid\Events\UzairAuthenticated;
use Uzairports\Uzairid\Events\UzairLoggedOut;
use Uzairports\Uzairid\Models\OauthToken;

/**
 * The endpoints behind `Uzair::routes()`.
 *
 * The whole handshake lives here rather than in each host application, so that
 * the ordering it depends on — one transaction, then the session, then the
 * events — is fixed in one place. Applications that need to change a step
 * extend this class and pass it to `Uzair::routes(['controller' => ...])`.
 */
class UzairAuthController
{
    public function redirect(): SymfonyRedirectResponse
    {
        return Socialite::driver('uzairports')->redirect();
    }

    /**
     * Complete the SSO handshake and open a session for the identity behind it.
     *
     * The account, authentication, and token are written in one atomic transaction:
     * `Auth::login()` migrates the session to prevent fixation, settling the final
     * session ID before the token row is persisted. If storing the token fails,
     * the transaction rolls back the account changes, the session is invalidated,
     * and the user is left unauthenticated.
     */
    public function callback(
        Request $request,
        ResolveUserFromSocialite $resolveUser,
        EndSessions $endSessions,
    ): RedirectResponse {
        if ($request->has('error')) {
            Log::info('UzAirports OAuth callback returned an error.');

            return $this->handshakeFailed(__('uzairid::messages.authentication_failed'));
        }

        try {
            /** @var SocialiteUser $uzairUser */
            $uzairUser = Socialite::driver('uzairports')->user();

            $previousSessionId = $this->sessionId($request);

            ['user' => $user, 'token' => $token] = $this->storeIdentity($request, $uzairUser, $resolveUser);
        } catch (InvalidStateException) {
            $this->reportLostHandshake($request);

            return $this->handshakeFailed(__('uzairid::messages.handshake_lost'));
        } catch (Throwable $e) {
            Auth::logout();
            if ($request->hasSession()) {
                $request->session()->invalidate();
                $request->session()->regenerateToken();
            }

            Log::error('UzAirports OAuth callback failed.', [
                'exception_class' => $e::class,
            ]);

            return $this->handshakeFailed(__('uzairid::messages.authentication_failed'));
        }

        $this->endPreviousLogin($endSessions, $token, $previousSessionId);

        if (config('uzairports.single_session', false)) {
            $endSessions(
                $this->accountKey($user),
                $token->session_id,
                revoke: (bool) config('uzairports.revoke_on_single_session', true),
            );
        }

        UzairAuthenticated::dispatch($user, $uzairUser, $token);

        return redirect()->intended($this->target(config('uzairports.redirect_to', 'dashboard')));
    }

    /**
     * Sign this device out, leaving the account's other devices alone.
     *
     * The token is dropped whether the identity provider accepted the
     * revocation: a provider that cannot be reached must not be able to keep a
     * user signed in here.
     */
    public function logout(Request $request, EndSessions $endSessions): JsonResponse|RedirectResponse
    {
        $user = Auth::user();

        if ($user !== null) {
            $token = OauthToken::query()
                ->where('user_id', $user->getAuthIdentifier())
                ->where('session_id', $this->sessionId($request))
                ->first();

            if ($token !== null) {
                $endSessions->end($token);
            }

            Auth::logout();

            UzairLoggedOut::dispatch($user);
        }

        return $this->finishLogout($request);
    }

    /**
     * Sign one of the account's logins out, named by its row.
     *
     * This is what a list of "your devices" needs: ending one of them without
     * touching the browser doing the ending. Naming the login by row id is safe     * . The lookup is scoped to the account — a row belonging to somebody
     * else is not refused but simply not found, so the endpoint cannot be used
     * to learn which ids exist.
     *
     * Ending the login this request is running on is signing yourself out, and
     * is handed to `logout()` so the session goes with it, rather than leaving
     * the browser authenticated against a row that no longer exists.
     */
    public function logoutDevice(Request $request, EndSessions $endSessions, int|string $token): JsonResponse|RedirectResponse
    {
        $user = Auth::user();

        $login = $user === null ? null : OauthToken::query()
            ->where('user_id', $user->getAuthIdentifier())
            ->whereKey($token)
            ->first();

        if ($login === null) {
            throw new NotFoundHttpException;
        }

        if ($login->session_id !== null && $login->session_id === $this->sessionId($request)) {
            return $this->logout($request, $endSessions);
        }

        $endSessions->end($login);

        return $request->wantsJson()
            ? new JsonResponse([], 204)
            : back();
    }

    /**
     * The account whose logins are about to be ended.
     *
     * `getAuthIdentifier()` promises nothing about what it hands back, and a
     * key that is neither an integer nor a string names no row: ending "the
     * logins of that" would either match nothing or, worse, match by whatever
     * the database made of it.
     *
     * @throws RuntimeException when the authenticated user has no usable key
     */
    private function accountKey(Authenticatable $user): int|string
    {
        $key = $user->getAuthIdentifier();

        if (! is_int($key) && ! is_string($key)) {
            throw new RuntimeException('The authenticated user has no key that names its logins.');
        }

        return $key;
    }

    /**
     * Record why a handshake arrived without the state it was started with.
     *
     * There are two of them, and the log line cannot be acted on without
     * knowing which:
     *
     * - No session cookie came back at all, so the browser never had one to
     *   send. That is a host mismatch — the flow was started on one name and
     *   `uzairports.redirect` brings it back on another, and a cookie set for
     *   `localhost` is not sent to `127.0.0.1`. Both must be the same name;
     * - The cookie came back and the state was gone, so the handshake was
     *   started twice — a second tab, a second click — and finished on the
     *   older one, whose state the newer had already replaced.
     */
    private function reportLostHandshake(Request $request): void
    {
        $cookie = config('session.cookie');

        Log::warning('UzAirports OAuth callback arrived without the state its handshake was started with.', [
            'session_cookie_received' => is_string($cookie) && $request->cookies->has($cookie),
            'callback_host' => $request->getSchemeAndHttpHost(),
            'configured_redirect' => config('uzairports.redirect'),
        ]);
    }

    /**
     * Send the user back where a failed handshake leaves them, with the reason.
     */
    private function handshakeFailed(string $message): RedirectResponse
    {
        return redirect()
            ->to($this->target(config('uzairports.redirect_on_error', '/')))
            ->withErrors(['oauth' => $message]);
    }

    /**
     * End the login this same browser was holding before it signed in again.
     *
     * Regenerating the session gives the browser a new id. The id names the row
     * — so without this, running the flow twice in one browser would
     * leave the first row behind, pointing at a session nobody can reach and
     * holding a grant nobody gave up.
     */
    private function endPreviousLogin(EndSessions $endSessions, OauthToken $token, ?string $previousSessionId): void
    {
        if ($previousSessionId === null || $previousSessionId === $token->session_id) {
            return;
        }

        OauthToken::query()
            ->where('user_id', $token->user_id)
            ->where('session_id', $previousSessionId)
            ->get()
            ->each(fn (OauthToken $stale) => $endSessions->end($stale));
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

    /**
     * Write the account and its token, retrying once if another callback won the race.
     *
     * Two callbacks for an identity with no local account, yet both see nothing
     * to update and both insert; the unique index on `users.uzair_id` refuses
     * the loser. Its transaction has already been rolled back by then, so the
     * work is simply done again — the second attempt finds the row the winner
     * wrote and updates it.
     *
     * @return array{user: Authenticatable&Model, token: OauthToken}
     *
     * @throws Throwable
     */
    private function storeIdentity(Request $request, SocialiteUser $uzairUser, ResolveUserFromSocialite $resolveUser): array
    {
        try {
            return $this->writeIdentity($request, $uzairUser, $resolveUser);
        } catch (UniqueConstraintViolationException) {
            return $this->writeIdentity($request, $uzairUser, $resolveUser);
        }
    }

    /**
     * @return array{user: Authenticatable&Model, token: OauthToken}
     *
     * @throws RuntimeException
     * @throws Throwable
     *                   when the configured auth model cannot be signed in
     */
    private function writeIdentity(Request $request, SocialiteUser $uzairUser, ResolveUserFromSocialite $resolveUser): array
    {
        return DB::transaction(function () use ($request, $uzairUser, $resolveUser): array {
            $user = $resolveUser($uzairUser);

            if (! $user instanceof Authenticatable) {
                throw new RuntimeException('The configured [auth.providers.users.model] cannot be authenticated.');
            }

            Auth::login($user);

            $sessionId = $this->sessionId($request);

            $token = OauthToken::query()->firstOrNew([
                'user_id' => $user->getKey(),
                'session_id' => $sessionId,
            ]);

            $token->forceFill([
                'user_id' => $user->getKey(),
                'session_id' => $sessionId,
                'access_token' => $uzairUser->token,
                'refresh_token' => $uzairUser->refreshToken,
                'expires_at' => $this->expiresAt($uzairUser),
                'ip_address' => $request->ip(),
                'user_agent' => Str::limit((string) $request->userAgent(), 500, ''),
            ])->save();

            return ['user' => $user, 'token' => $token];
        });
    }

    /**
     * Resolve the moment the issued access token stops being accepted.
     *
     * The identity provider does not have to say how long the token lives.
     * Unknown expiry is stored as null, which the refresh middleware treats as
     * expired, so the token is renewed on the next request rather than used
     * until it is refused.
     */
    private function expiresAt(SocialiteUser $uzairUser): ?CarbonInterface
    {
        if ($uzairUser->expiresIn === null) {
            return null;
        }

        return now()->addSeconds((int) $uzairUser->expiresIn);
    }

    /**
     * The session this request belongs to, if it belongs to one at all.
     */
    private function sessionId(Request $request): ?string
    {
        return $request->hasSession() ? $request->session()->getId() : null;
    }

    /**
     * Turn a configured destination — a route name or a path — into a URL.
     */
    private function target(mixed $destination): string
    {
        $destination = is_string($destination) && $destination !== '' ? $destination : '/';

        return Route::has($destination) ? route($destination) : url($destination);
    }
}
