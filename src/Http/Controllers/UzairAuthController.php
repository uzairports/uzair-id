<?php

namespace Uzairports\Uzairid\Http\Controllers;

use Carbon\CarbonInterface;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\QueryException;
use Illuminate\Database\UniqueConstraintViolationException;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Schema;
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
 * the ordering it depends on — the account, then the session, then the login
 * that names it, then the events — is fixed in one place. Applications that
 * need to change a step extend this class and pass it to
 * `Uzair::routes(['controller' => ...])`.
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
     * The account is written, then the browser is signed in — `Auth::login()`
     * migrates the session to prevent fixation, settling the final session id —
     * and then the token row is written against that id. Each write is atomic
     * in itself; the sign-in between them is deliberately not inside either,
     * because it fires events a host application listens to. See
     * `storeIdentity()`.
     *
     * Anything failing along the way leaves the browser unauthenticated: the
     * session is invalidated, the grants the handshake was already issued are
     * handed back — see `surrenderIssuedGrants()` — and the user is sent back
     * with the reason.
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

        $uzairUser = null;

        try {
            /** @var SocialiteUser $uzairUser */
            $uzairUser = Socialite::driver('uzairports')->user();

            $previousSessionId = $this->sessionId($request);

            ['user' => $user, 'token' => $token] = $this->storeIdentity($request, $uzairUser, $resolveUser);
        } catch (InvalidStateException) {
            $this->reportLostHandshake($request);

            return $this->handshakeFailed(__('uzairid::messages.handshake_lost'));
        } catch (Throwable $e) {
            $this->surrenderIssuedGrants($endSessions, $uzairUser);

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

        // Two callbacks for one account finishing at the same moment each write
        // their own row and then end "the others", which by then includes the
        // row the other one just wrote: both logins can go, and both browsers
        // are sent back through SSO on their next request. That is left
        // unserialized on purpose. Closing it means holding a lock on the
        // account across the write and the sweep — on the sign-in path, for
        // every sign-in — to buy an outcome that differs from the intended one
        // only in which of two simultaneous logins survives. `single_session`
        // promises that one login stands at a time, and ending both keeps that
        // promise the strict way: nothing is left signed in that should not be,
        // and signing in again is one redirect.
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
            $tokens = OauthToken::query()->where('user_id', $user->getAuthIdentifier());

            $token = $request->hasSession()
                ? $tokens->where('session_id', $this->sessionId($request))->first()
                : $tokens->whereNull('session_id')->latest('id')->first();

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
     * touching the browser doing the ending. Naming the login by row id is
     * safe: the lookup is scoped to the account — a row belonging to somebody
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
     * `writeAccount()` asks for the key inside the transaction that writes the
     *  account before the browser is signed in, so a model that cannot answer
     * fails the handshake rather than this call, which runs once the browser is
     * already signed in.
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
     * Hand back the grants a handshake was issued before it failed.
     *
     * The authorization code has already been exchanged by the time anything
     * here can fail, so a callback that cannot finish is holding a live access
     * token and a live refresh token, and nothing was written: the failure is
     * either the account or the login row, and neither reaches the database
     * with these values in it. `EndSessions::surrenderIssued()` is where that
     * is answered, and what it says about grants no row points at.
     *
     * This covers the failures from `Auth::login()` onward. A profile request
     * that fails is the other half, and never reaches here — `user()` throws
     * before it can hand a user back, so there is nothing to read the grants
     * off. The driver surrenders those itself, where they are still in hand.
     *
     * Nothing raises out of here. The caller is in the middle of answering a
     * failure and must go on to sign the browser out and report the original
     * exception, which is the one worth reading; `EndSessions` already reports
     * a revocation that would not go through.
     */
    private function surrenderIssuedGrants(EndSessions $endSessions, ?SocialiteUser $uzairUser): void
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
     *
     * There may be more than one row: the id names a session, not an account,
     * and a shared computer or a second identity leaves several. They are ended
     * together rather than one after the next, so the browser waiting on this
     * callback pays one revocation wait instead of one apiece.
     */
    private function endPreviousLogin(EndSessions $endSessions, OauthToken $token, ?string $previousSessionId): void
    {
        if ($previousSessionId === null || $previousSessionId === $token->session_id) {
            return;
        }

        $endSessions->endAll(
            OauthToken::query()->where('session_id', $previousSessionId)->get()
        );
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
     * Write the account, sign it in, and record the login this browser made.
     *
     * The three steps are ordered by what each needs from the one before, and
     * the sign-in is deliberately not inside a transaction. `Auth::login()`
     * fires `Illuminate\Auth\Events\Login`, and a host application's listeners
     * are entitled to see a committed account: one dispatching a queued job saw
     * a worker pick it up before the row it names existed, and one reading over
     * a second connection saw no account at all. Wrapping somebody else's
     * listeners in a transaction this class opened is not this package's call
     * to make.
     *
     * What that gives up is rolling the account back when the token cannot be
     * stored. It is worth little: the row that would be rolled back is the
     * profile of an identity that just authenticated successfully, the caller
     * signs the browser out either way, and the account is left linked so the
     * next attempt finds it instead of racing for it again. Each of the two
     * writes is still atomic in itself.
     *
     * @return array{user: Authenticatable&Model, token: OauthToken}
     *
     * @throws Throwable
     */
    private function storeIdentity(Request $request, SocialiteUser $uzairUser, ResolveUserFromSocialite $resolveUser): array
    {
        $user = $this->storeAccount($uzairUser, $resolveUser);

        Auth::login($user);

        return ['user' => $user, 'token' => $this->storeToken($request, $uzairUser, $user)];
    }

    /**
     * Resolve the account behind the identity, retrying once if another
     * callback won the race.
     *
     * Two callbacks for an identity with no local account, yet both see nothing
     * to update and both insert; the unique index on `users.uzair_id` refuses
     * the loser. Its transaction has already been rolled back by then, so the
     * work is simply done again — the second attempt finds the row the winner
     * wrote and updates it.
     *
     * A refusal that is not that race is not something the retry can help with,
     * and both of the ones an integrator actually meets come from the accounts
     * table still being shaped for local passwords — see
     * `refuseTheAccountWrite()`, which is what says so.
     *
     * @return Authenticatable&Model
     *
     * @throws Throwable
     */
    private function storeAccount(SocialiteUser $uzairUser, ResolveUserFromSocialite $resolveUser): Authenticatable
    {
        try {
            return $this->writeAccount($uzairUser, $resolveUser);
        } catch (UniqueConstraintViolationException) {
            // Another callback inserted the account first. Its transaction is
            // rolled back by now, so the work is done again below.
        } catch (QueryException $exception) {
            $this->refuseTheAccountWrite($exception);
        }

        try {
            return $this->writeAccount($uzairUser, $resolveUser);
        } catch (QueryException $exception) {
            $this->refuseTheAccountWrite($exception);
        }
    }

    /**
     * Say what about the accounts table refused the write, then hand it on.
     *
     * The database refusing this write is what a standard Laravel `users` table
     * does to an SSO sign-in, and there are two of them. `password` is `NOT
     * NULL` with no default, and nothing here has a password to write. `email`
     * is unique and `NOT NULL`, while the identity provider does not promise an
     * address at all and lets two accounts share one — so the first person
     * whose address already exists locally cannot sign in, and neither can the
     * second holder of a shared one. The package publishes
     * `remove_password_column_from_users_table` and
     * `relax_email_column_on_users_table` for exactly this, under the
     * `uzairid-user-migrations` tag.
     *
     * What used to happen when they were skipped is why this exists at all: the
     * failure went to the handshake's own handler, which writes the exception
     * class and nothing else, and the browser was sent back with
     * "authentication failed". Nothing connected either to a column, and the
     * integrator had a working OAuth flow that refused every new account.
     *
     * The table is read rather than the driver's message parsed. Three drivers
     * word these two refusals five different ways; the schema says the same
     * thing on all of them, and says it about this application's own table.
     *
     * Nothing here may raise. A diagnosis that fails must not replace the
     * failure it was diagnosing, so the original exception goes on either way.
     *
     * @throws QueryException always
     */
    private function refuseTheAccountWrite(QueryException $exception): never
    {
        Log::error('The account behind an UzAirports identity could not be written.', [
            'exception_class' => $exception::class,
            ...$this->accountsTableComplaints(),
        ]);

        throw $exception;
    }

    /**
     * What about the accounts table would refuse a write this package makes.
     *
     * @return array<string, mixed>
     */
    private function accountsTableComplaints(): array
    {
        try {
            $table = $this->accountsTable();

            if ($table === null) {
                return [];
            }

            return [
                'accounts_table' => $table,
                'email_is_unique' => Schema::hasIndex($table, ['email'], 'unique'),
                'columns_needing_a_value' => $this->columnsNeedingAValue($table),
                'remedy' => 'php artisan vendor:publish --tag=uzairid-user-migrations',
            ];
        } catch (Throwable) {
            return [];
        }
    }

    /**
     * The columns a new account cannot be written without.
     *
     * A column that forbids null, has no default and is not filled in by the
     * database itself has to come from whoever inserts the row — and the
     * package fills in only the three it knows about. `password` is the one
     * this finds on a standard installation, and naming it is the whole point:
     * an application on a hybrid scheme keeps the column and makes it nullable,
     * one on SSO alone drops it, and neither can tell which it needs to do from
     * a log line reading `QueryException`.
     *
     * @return list<string>
     */
    private function columnsNeedingAValue(string $table): array
    {
        $written = ['uzair_id', 'name', 'email', 'created_at', 'updated_at'];

        $needed = [];

        foreach (Schema::getColumns($table) as $column) {
            $name = (string) $column['name'];

            if (in_array($name, $written, true) || ($column['auto_increment'] ?? false) === true) {
                continue;
            }

            if (($column['nullable'] ?? true) === false && ($column['default'] ?? null) === null) {
                $needed[] = $name;
            }
        }

        return $needed;
    }

    /**
     * The table the host application keeps its accounts in.
     */
    private function accountsTable(): ?string
    {
        $model = config('auth.providers.users.model');

        if (! is_string($model) || ! class_exists($model)) {
            return null;
        }

        $user = new $model;

        return $user instanceof Model ? $user->getTable() : null;
    }

    /**
     * @return Authenticatable&Model
     *
     * @throws RuntimeException when the configured auth model cannot be signed in
     * @throws Throwable
     */
    private function writeAccount(SocialiteUser $uzairUser, ResolveUserFromSocialite $resolveUser): Authenticatable
    {
        return DB::transaction(function () use ($uzairUser, $resolveUser): Authenticatable {
            $user = $resolveUser($uzairUser);

            if (! $user instanceof Authenticatable) {
                throw new RuntimeException('The configured [auth.providers.users.model] cannot be authenticated.');
            }

            // The account has to be in the database to be signed in, and
            // `save()` answers false rather than raising when a listener
            // refuses the write. Left unasked, `Auth::login()` would fire the
            // `Login` event naming a model with no key, and the login row
            // written next would carry a null `user_id` into the foreign key.
            if (! $user->exists) {
                throw new RuntimeException('The account behind this UzAirports identity was not written.');
            }

            // `single_session` ends the account's other logins once this one is
            // written and names them by whatever `getAuthIdentifier()` hands
            // back. A key that names no row is asked for here, before the
            // browser is signed in, rather than where it is spent: raised on
            // the far side, the account would already be written and signed in,
            // and a handshake that worked would end in a 500.
            if (config('uzairports.single_session', false)) {
                $this->accountKey($user);
            }

            return $user;
        });
    }

    /**
     * Record the login, retrying once if another callback won the same session.
     *
     * The session id is settled by now: `Auth::login()` migrated the session to
     * prevent fixation before this is called, so the row names the id the
     * browser will actually carry. Two callbacks finishing on one session would
     * both find nothing and both insert, and `(user_id, session_id)` refuses
     * the loser — which retries and updates what the winner wrote.
     *
     * @param  Authenticatable&Model  $user
     *
     * @throws Throwable
     */
    private function storeToken(Request $request, SocialiteUser $uzairUser, Authenticatable $user): OauthToken
    {
        try {
            return $this->writeToken($request, $uzairUser, $user);
        } catch (UniqueConstraintViolationException) {
            return $this->writeToken($request, $uzairUser, $user);
        }
    }

    /**
     * Write the login row, refusing the handshake if the write did not happen.
     *
     * `save()` answers false rather than raising when a `saving` or `creating`
     * listener returns false, and that answer used to be dropped. The handshake
     * then carried on as though it had succeeded: the browser stayed signed in
     * against a row that was never written — or, where the row already existed,
     * one still holding the grants of the previous login — the freshly issued
     * grants were never handed back, `UzairAuthenticated` was dispatched naming
     * a model that does not exist, and under `single_session` the sweep that
     * follows ended every other login of the account on behalf of one that had
     * not been recorded. The browser was then refused by `uzair.token` on its
     * very next request and sent back to sign in again, which is a loop.
     *
     * A listener that refuses the write is saying this login must not be
     * recorded, and the only coherent answer is not to sign the browser in.
     * Raising puts it through the same cleanup as any other failed handshake:
     * the session is dropped and the grants are surrendered. It is the same
     * respect `EndSessions` already pays a `deleting` listener that refuses to
     * let a row go.
     *
     * @param  Authenticatable&Model  $user
     *
     * @throws RuntimeException when the write was refused without raising
     * @throws Throwable
     */
    private function writeToken(Request $request, SocialiteUser $uzairUser, Authenticatable $user): OauthToken
    {
        $sessionId = $this->sessionId($request);

        $token = OauthToken::query()->firstOrNew([
            'user_id' => $user->getKey(),
            'session_id' => $sessionId,
        ]);

        $saved = $token->forceFill([
            'user_id' => $user->getKey(),
            'session_id' => $sessionId,
            'access_token' => $uzairUser->token,
            'refresh_token' => $uzairUser->refreshToken,
            'expires_at' => $this->expiresAt($uzairUser),
            'ip_address' => $request->ip(),
            'user_agent' => Str::limit((string) $request->userAgent(), 500, ''),
        ])->save();

        if (! $saved) {
            throw new RuntimeException('The UzAirports login was refused by a model listener and not recorded.');
        }

        return $token;
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
