<?php

namespace Uzairports\Uzairid\Http\Controllers;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Str;
use Illuminate\Validation\Rule;
use Illuminate\Validation\ValidationException;
use Laravel\Sanctum\NewAccessToken;
use Laravel\Socialite\Facades\Socialite;
use Laravel\Socialite\Two\User as SocialiteUser;
use RuntimeException;
use Throwable;
use Uzairports\Uzairid\Actions\EndSessions;
use Uzairports\Uzairid\Actions\EnsureTokenStorageMatchesProvider;
use Uzairports\Uzairid\Actions\ResolveUserFromSocialite;
use Uzairports\Uzairid\Events\UzairAuthenticated;
use Uzairports\Uzairid\Models\OauthToken;
use Uzairports\Uzairid\Socialite\UzairportsProvider;
use Uzairports\Uzairid\Uzair;

/**
 * The endpoints behind `Uzair::apiRoutes()`, for a mobile client.
 *
 * A browser is signed in by a session, which a mobile client does not hold.
 * It is handed a Sanctum token instead, and its login row is filed under that
 * token the way a browser's is filed under its session — so `uzair.token`
 * renews it, `logoutDevice` lists and ends it, and ending it deletes the token.
 *
 * `logout` and `logoutDevice` are the browser endpoints, read off the API guard.
 */
class UzairApiAuthController extends UzairAuthController
{
    /**
     * Trade an authorization code the client obtained for a Sanctum token.
     *
     * The order is the callback's: the account, then the login, then the
     * events. The Sanctum token and the login row are written in one
     * transaction, so neither exists without the other.
     *
     * Anything failing after the exchange hands the issued grants back, as the
     * callback does, and the client is told only that the sign-in failed; the
     * log says why.
     *
     * @throws ValidationException
     */
    public function token(Request $request, ResolveUserFromSocialite $resolveUser, EndSessions $endSessions): JsonResponse
    {
        $validated = $request->validate([
            'code' => ['required', 'string', 'max:2048'],
            'redirect_uri' => ['required', 'string', Rule::in(Uzair::apiRedirectUris())],
            'code_verifier' => [
                config('uzairports.pkce', true) ? 'required' : 'nullable',
                'string',
                'min:43',
                'max:128',
                'regex:/^[A-Za-z0-9\-._~]+$/',
            ],
            'device_name' => ['required', 'string', 'max:255'],
        ]);

        $uzairUser = null;

        try {
            app(EnsureTokenStorageMatchesProvider::class)();

            $this->ensureSanctumCanIssueTokens();

            $uzairUser = $this->provider()->userFromCode(
                $validated['code'],
                $validated['redirect_uri'],
                $validated['code_verifier'] ?? null,
            );

            $user = $this->storeAccount($uzairUser, $resolveUser);

            ['login' => $login, 'plainTextToken' => $plainTextToken] = $this->issueAccessToken(
                $request, $uzairUser, $user, $validated['device_name'],
            );
        } catch (Throwable $e) {
            $this->surrenderIssuedGrants($endSessions, $uzairUser);

            Log::error('UzAirports API token exchange failed.', [
                'exception_class' => $e::class,
            ]);

            return new JsonResponse(['message' => __('uzairid::messages.authentication_failed')], 401);
        }

        // See the callback: `single_session` ends the account's other logins,
        // browsers and phones alike, and spares the one just written by its row.
        if (config('uzairports.single_session', false)) {
            $endSessions(
                $this->accountKey($user),
                revoke: (bool) config('uzairports.revoke_on_single_session', true),
                exceptLoginId: $login->id,
            );
        }

        UzairAuthenticated::dispatch($user, $uzairUser, $login);

        return new JsonResponse([
            'token' => $plainTextToken,
            'token_type' => 'Bearer',
        ]);
    }

    protected function guardName(): string
    {
        return Uzair::apiGuard();
    }

    /**
     * Refuse before the code is spent if no Sanctum token could be issued.
     *
     * Exchanging first would leave a grant to surrender on every attempt of a
     * misconfigured application, for a failure known in advance.
     *
     * @throws RuntimeException when Sanctum or `HasApiTokens` is missing
     */
    private function ensureSanctumCanIssueTokens(): void
    {
        if (Uzair::accessTokenModel() === null) {
            throw new RuntimeException('Issuing tokens to mobile clients needs laravel/sanctum.');
        }

        if (! method_exists(Uzair::userModel(), 'createToken')) {
            throw new RuntimeException('The account model must use Laravel\Sanctum\HasApiTokens to be issued a token.');
        }
    }

    /**
     * The driver, checked rather than annotated.
     *
     * @throws RuntimeException when the `uzairports` driver is not this package's
     */
    private function provider(): UzairportsProvider
    {
        $provider = Socialite::driver('uzairports');

        if (! $provider instanceof UzairportsProvider) {
            throw new RuntimeException('The [uzairports] Socialite driver is not '.UzairportsProvider::class.'.');
        }

        return $provider;
    }

    /**
     * Write the Sanctum token and the login filed under it, together.
     *
     * A refused `save()` raises, for the reason `writeToken()` gives, and takes
     * the Sanctum token back with the transaction.
     *
     * @param  Authenticatable&Model  $user
     * @return array{login: OauthToken, plainTextToken: string}
     *
     * @throws Throwable
     */
    private function issueAccessToken(Request $request, SocialiteUser $uzairUser, Authenticatable $user, string $deviceName): array
    {
        return OauthToken::query()->getConnection()->transaction(function () use ($request, $uzairUser, $user, $deviceName): array {
            $accessToken = method_exists($user, 'createToken') ? $user->createToken($deviceName) : null;

            if (! $accessToken instanceof NewAccessToken) {
                throw new RuntimeException('The account model did not issue a Sanctum token.');
            }

            $records = (bool) config('uzairports.record_device', true);

            $login = (new OauthToken)->forceFill([
                'user_id' => $user->getKey(),
                'session_id' => null,
                'personal_access_token_id' => $accessToken->accessToken->getKey(),
                'access_token' => $uzairUser->token,
                'refresh_token' => $uzairUser->refreshToken,
                'expires_at' => $this->expiresAt($uzairUser),
                'ip_address' => $records ? $request->ip() : null,
                'user_agent' => $records ? Str::limit((string) $request->userAgent(), 500, '') : null,
            ]);

            if (! $login->save()) {
                throw new RuntimeException('The UzAirports login was refused by a model listener and not recorded.');
            }

            return ['login' => $login, 'plainTextToken' => $accessToken->plainTextToken];
        });
    }
}
