<?php

namespace Uzairports\Uzairid\Http\Controllers;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\StatefulGuard;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use Laravel\Socialite\Facades\Socialite;
use Laravel\Socialite\Two\InvalidStateException;
use Laravel\Socialite\Two\User as SocialiteUser;
use RuntimeException;
use Symfony\Component\HttpFoundation\RedirectResponse as SymfonyRedirectResponse;
use Throwable;
use Uzairports\Uzairid\Actions\EndSessions;
use Uzairports\Uzairid\Actions\EnsureTokenStorageMatchesProvider;
use Uzairports\Uzairid\Actions\RecordLogin;
use Uzairports\Uzairid\Actions\ResolveUserFromSocialite;
use Uzairports\Uzairid\Actions\StoreAccount;
use Uzairports\Uzairid\Events\UzairAuthenticated;
use Uzairports\Uzairid\Models\OauthToken;
use Uzairports\Uzairid\Uzair;

/**
 * The browser endpoints behind `Uzair::routes()`.
 *
 * The handshake's order — the account, then the session, then the login that
 * names it, then the events — is fixed here. Applications that need to change
 * a step extend this class and pass it to `Uzair::routes(['controller' => ...])`.
 */
class UzairAuthController extends UzairController
{
    public function redirect(): SymfonyRedirectResponse
    {
        return Socialite::driver('uzairports')->redirect();
    }

    /**
     * Complete the SSO handshake and open a session for the identity behind it.
     *
     * Anything failing after the code exchange leaves the browser signed out:
     * the session is invalidated, the issued grants are surrendered, and the
     * browser is sent back with the reason.
     *
     * Under `single_session` the account's other logins end once this one is
     * written. Two sign-ins finishing at once may end each other; that is left
     * unserialized on purpose — it keeps the one-login promise the strict way,
     * and signing in again is one redirect.
     *
     * @throws Throwable
     */
    public function callback(
        Request $request,
        ResolveUserFromSocialite $resolveUser,
        EndSessions $endSessions,
    ): RedirectResponse {
        if ($request->has('error')) {
            return $this->authorizationRefused($request->query('error'));
        }

        $uzairUser = null;
        $storeAccount = app(StoreAccount::class, ['resolveUser' => $resolveUser]);

        try {
            app(EnsureTokenStorageMatchesProvider::class)();

            /** @var SocialiteUser $uzairUser */
            $uzairUser = Socialite::driver('uzairports')->user();

            $previousSessionIds = Uzair::loginSessionIds($request);

            ['user' => $user, 'token' => $token] = $this->storeIdentity($request, $uzairUser, $storeAccount);
        } catch (InvalidStateException) {
            $this->reportLostHandshake($request);

            return $this->handshakeFailed(__('uzairid::messages.handshake_lost'));
        } catch (Throwable $e) {
            $this->surrenderIssuedGrants($endSessions, $uzairUser);

            $this->signOut();
            if ($request->hasSession()) {
                $request->session()->invalidate();
                $request->session()->regenerateToken();
            }

            Log::error('UzAirports OAuth callback failed.', [
                'exception_class' => $e::class,
            ]);

            return $this->handshakeFailed(__('uzairid::messages.authentication_failed'));
        }

        $this->endPreviousLogin($endSessions, $token, $previousSessionIds);

        $this->noteTheBrowsersLogin($request);

        if (config('uzairports.single_session', false)) {
            $endSessions(
                $storeAccount->keyOf($user),
                $token->session_id,
                revoke: (bool) config('uzairports.revoke_on_single_session', true),
            );
        }

        UzairAuthenticated::dispatch($user, $uzairUser, $token);

        return redirect()->intended($this->target(config('uzairports.redirect_to', 'dashboard')));
    }

    /**
     * Write the account, sign it in, and record the login this browser made.
     *
     * The sign-in sits between the two writes, outside both transactions:
     * `Auth::login()` fires `Login`, whose listeners must see a committed
     * account, and it migrates the session, settling the id the login is
     * recorded under. A login that cannot be recorded therefore leaves the
     * account linked, which is what the next attempt wants anyway.
     *
     * @return array{user: Authenticatable&Model, token: OauthToken}
     *
     * @throws Throwable
     */
    private function storeIdentity(Request $request, SocialiteUser $uzairUser, StoreAccount $storeAccount): array
    {
        $user = $storeAccount($uzairUser);

        $this->statefulGuard()->login($user);

        $token = app(RecordLogin::class)($request, $uzairUser, $user, $this->sessionId($request));

        return ['user' => $user, 'token' => $token];
    }

    /**
     * The guard a sign-in can be recorded in; one holding no session is a
     * misconfiguration the callback fails on.
     *
     * @throws RuntimeException when the configured guard holds no session
     */
    private function statefulGuard(): StatefulGuard
    {
        return $this->sessionGuard()
            ?? throw new RuntimeException('The guard named by [uzairports.guard] cannot sign a browser in.');
    }

    /**
     * Log which of the two causes lost the handshake's state.
     *
     * No session cookie came back: the flow started on one host name and
     * `uzairports.redirect` returns on another. The cookie came back without
     * the state: the handshake was started twice and finished on the older one.
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
     * The RFC 6749 §4.1.2.1 codes an authorization request may be refused with.
     *
     * Only these are logged; anything else in the query string is the
     * browser's to write and is logged as `other`.
     *
     * @var list<string>
     */
    private const array AUTHORIZATION_ERRORS = [
        'access_denied',
        'invalid_request',
        'invalid_scope',
        'server_error',
        'temporarily_unavailable',
        'unauthorized_client',
        'unsupported_response_type',
    ];

    /**
     * Answer a callback the identity provider sent back with an `error`.
     *
     * The user declining is ordinary and said so; the provider failing is
     * told as an outage; anything else points at this application's
     * registration, so it is a warning for an operator. `error_description`
     * is never logged, since anyone can put anything in it.
     */
    private function authorizationRefused(mixed $error): RedirectResponse
    {
        $error = in_array($error, self::AUTHORIZATION_ERRORS, true) ? $error : 'other';

        if ($error === 'access_denied') {
            Log::info('UzAirports OAuth authorization was declined.');

            return $this->handshakeFailed(__('uzairid::messages.access_denied'));
        }

        Log::warning('UzAirports OAuth callback returned an error.', ['oauth_error' => $error]);

        if ($error === 'server_error' || $error === 'temporarily_unavailable') {
            return $this->handshakeFailed(__('uzairid::messages.temporarily_unavailable'));
        }

        return $this->handshakeFailed(__('uzairid::messages.authentication_failed'));
    }

    private function handshakeFailed(string $message): RedirectResponse
    {
        return redirect()
            ->to($this->target(config('uzairports.redirect_on_error', '/')))
            ->withErrors(['oauth' => $message]);
    }

    /**
     * Note which session id this login is filed under, and that it is an SSO
     * login: a later regeneration is followed from this note, and a mark left
     * by a password sign-in in this session no longer applies.
     *
     * The note is overwritten rather than followed — the login it named before
     * is the one `endPreviousLogin()` has just ended.
     */
    private function noteTheBrowsersLogin(Request $request): void
    {
        Uzair::rememberSession($request);
        Uzair::forgetLocalSession($request);
    }

    /**
     * End the logins this browser held before signing in again.
     *
     * Signing in gives the session a new id, so the earlier login would be left
     * pointing at a session nobody holds. The id names a session, not an
     * account, so several rows may go — together, in one revocation wait.
     *
     * @param  list<string>  $previousSessionIds
     */
    private function endPreviousLogin(EndSessions $endSessions, OauthToken $token, array $previousSessionIds): void
    {
        $previousSessionIds = array_filter(
            $previousSessionIds,
            fn (string $sessionId): bool => $sessionId !== $token->session_id,
        );

        if ($previousSessionIds === []) {
            return;
        }

        $endSessions->endAll(
            OauthToken::query()->whereIn('session_id', $previousSessionIds)->get()
        );
    }
}
