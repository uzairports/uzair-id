<?php

namespace Uzairports\Uzairid\Http\Controllers;

use Carbon\CarbonInterface;
use Illuminate\Auth\AuthenticationException;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use Illuminate\Validation\Rule;
use Illuminate\Validation\ValidationException;
use Laravel\Sanctum\NewAccessToken;
use Laravel\Socialite\Facades\Socialite;
use Laravel\Socialite\Two\User as SocialiteUser;
use RuntimeException;
use Throwable;
use Uzairports\Uzairid\Actions\EndSessions;
use Uzairports\Uzairid\Actions\EnsureTokenStorageMatchesProvider;
use Uzairports\Uzairid\Actions\RecordLogin;
use Uzairports\Uzairid\Actions\RefreshAccessToken;
use Uzairports\Uzairid\Actions\ResolveUserFromSocialite;
use Uzairports\Uzairid\Actions\StoreAccount;
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
 * `logout` and `logoutDevice` are the shared ones, read off the API guard.
 */
class UzairApiAuthController extends UzairController
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
                config('uzairports.api.pkce', true) ? 'required' : 'nullable',
                'string',
                'min:43',
                'max:128',
                'regex:/^[A-Za-z0-9\-._~]+$/',
            ],
            'device_name' => ['required', 'string', 'max:255'],
        ]);

        $uzairUser = null;
        $login = null;
        $storeAccount = app(StoreAccount::class, ['resolveUser' => $resolveUser]);

        try {
            app(EnsureTokenStorageMatchesProvider::class)();

            $this->ensureSanctumCanIssueTokens();

            $uzairUser = $this->provider()->userFromCode(
                $validated['code'],
                $validated['redirect_uri'],
                $validated['code_verifier'] ?? null,
            );

            $user = $storeAccount($uzairUser);

            ['login' => $login, 'plainTextToken' => $plainTextToken, 'expiresAt' => $expiresAt] = $this->issueAccessToken(
                $request, $uzairUser, $user, $validated['device_name'],
            );

            // See the callback: `single_session` ends the account's other logins,
            // browsers and phones alike, and spares the one just written by its row.
            if (config('uzairports.single_session', false)) {
                $endSessions(
                    $storeAccount->keyOf($user),
                    revoke: (bool) config('uzairports.revoke_on_single_session', true),
                    exceptLoginId: $login->id,
                );
            }

            UzairAuthenticated::dispatch($user, $uzairUser, $login);
        } catch (Throwable $e) {
            $this->abandon($endSessions, $uzairUser, $login);

            Log::error('UzAirports API token exchange failed.', [
                'exception_class' => $e::class,
            ]);

            return new JsonResponse(['message' => __('uzairid::messages.authentication_failed')], 401);
        }

        return new JsonResponse([
            'token' => $plainTextToken,
            'token_type' => 'Bearer',
            'expires_at' => $expiresAt?->toIso8601String(),
        ]);
    }

    /**
     * Refresh the mobile client's Sanctum token and remote grant.
     *
     * A `device_name` renames the token, under the same rule `token()` applies.
     *
     * @throws ValidationException
     */
    public function refresh(Request $request, RefreshAccessToken $refreshAccessToken, EndSessions $endSessions): JsonResponse
    {
        $user = $this->authenticated();

        if ($user === null) {
            return new JsonResponse(['message' => __('uzairid::messages.session_ended')], 401);
        }

        $validated = $request->validate([
            'device_name' => ['nullable', 'string', 'max:255'],
        ]);

        $accessTokenId = Uzair::accessTokenId($user);

        if ($accessTokenId === null) {
            return new JsonResponse(['message' => __('uzairid::messages.session_ended')], 401);
        }

        $login = OauthToken::query()
            ->where('user_id', $user->getAuthIdentifier())
            ->where('personal_access_token_id', $accessTokenId)
            ->first();

        if ($login === null) {
            return new JsonResponse(['message' => __('uzairid::messages.session_ended')], 401);
        }

        try {
            $refreshLeeway = config('uzairports.refresh_leeway', 60);
            $leeway = is_numeric($refreshLeeway) ? (int) $refreshLeeway : 60;

            if ($login->hasExpired() || $login->expiresWithin($leeway)) {
                $refreshed = $refreshAccessToken($login, $leeway);

                if (! $refreshed) {
                    $endSessions->end($login);

                    return new JsonResponse(['message' => __('uzairid::messages.session_expired')], 401);
                }
            }

            $rawDeviceName = $validated['device_name'] ?? null;
            $deviceName = is_string($rawDeviceName) && $rawDeviceName !== ''
                ? $rawDeviceName
                : ($login->deviceLabel() ?: 'Mobile Client');
            $expiresAt = $this->tokenExpiresAt();

            ['plainTextToken' => $plainTextToken, 'expiresAt' => $newExpiresAt] = OauthToken::query()
                ->getConnection()
                ->transaction(function () use ($user, $login, $deviceName, $expiresAt, $endSessions, $accessTokenId): array {
                    $lockedLogin = OauthToken::query()
                        ->whereKey($login->getKey())
                        ->lockForUpdate()
                        ->first();

                    if ($lockedLogin === null || (string) $lockedLogin->personal_access_token_id !== (string) $accessTokenId) {
                        throw new AuthenticationException(__('uzairid::messages.session_ended'));
                    }

                    $newAccessToken = method_exists($user, 'createToken')
                        ? $user->createToken($deviceName, $this->tokenAbilities(), $expiresAt)
                        : null;

                    if (! $newAccessToken instanceof NewAccessToken) {
                        throw new RuntimeException('The account model did not issue a Sanctum token.');
                    }

                    $newKey = $newAccessToken->accessToken->getKey();

                    $lockedLogin->forceFill(['personal_access_token_id' => $newKey])->save();

                    $endSessions->dropAccessTokens([$accessTokenId]);

                    return [
                        'plainTextToken' => $newAccessToken->plainTextToken,
                        'expiresAt' => $expiresAt ?? $this->globalExpiry($newAccessToken),
                    ];
                });
        } catch (AuthenticationException $e) {
            return new JsonResponse(['message' => $e->getMessage()], 401);
        } catch (Throwable $e) {
            Log::error('UzAirports API token refresh failed.', [
                'exception_class' => $e::class,
            ]);

            return new JsonResponse(['message' => __('uzairid::messages.temporarily_unavailable')], 503);
        }

        return new JsonResponse([
            'token' => $plainTextToken,
            'token_type' => 'Bearer',
            'expires_at' => $newExpiresAt?->toIso8601String(),
        ]);
    }

    /**
     * Undo what a failed exchange left behind.
     *
     * Once the login is written, the client that never received its token
     * cannot end it, so it is ended here — Sanctum token and grants with it.
     * Before that, only the issued grants exist to surrender. Never raises.
     */
    private function abandon(EndSessions $endSessions, ?SocialiteUser $uzairUser, ?OauthToken $login): void
    {
        if ($login === null) {
            $this->surrenderIssuedGrants($endSessions, $uzairUser);

            return;
        }

        try {
            $endSessions->end($login);
        } catch (Throwable $exception) {
            Log::warning('Failed to end an UzAirports login whose token could not be handed to the client.', [
                'exception_class' => $exception::class,
            ]);
        }
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
     * One transaction, so a login that cannot be recorded takes its Sanctum
     * token back with it.
     *
     * @param  Authenticatable&Model  $user
     * @return array{login: OauthToken, plainTextToken: string, expiresAt: CarbonInterface|null}
     *
     * @throws Throwable
     */
    private function issueAccessToken(Request $request, SocialiteUser $uzairUser, Authenticatable $user, string $deviceName): array
    {
        $expiresAt = $this->tokenExpiresAt();

        return OauthToken::query()->getConnection()->transaction(function () use ($request, $uzairUser, $user, $deviceName, $expiresAt): array {
            $accessToken = method_exists($user, 'createToken')
                ? $user->createToken($deviceName, $this->tokenAbilities(), $expiresAt)
                : null;

            if (! $accessToken instanceof NewAccessToken) {
                throw new RuntimeException('The account model did not issue a Sanctum token.');
            }

            $accessTokenId = $accessToken->accessToken->getKey();

            if (! is_int($accessTokenId) && ! is_string($accessTokenId)) {
                throw new RuntimeException('The issued Sanctum token has no key a login can be filed under.');
            }

            $login = app(RecordLogin::class)($request, $uzairUser, $user, null, $accessTokenId);

            return [
                'login' => $login,
                'plainTextToken' => $accessToken->plainTextToken,
                'expiresAt' => $expiresAt ?? $this->globalExpiry($accessToken),
            ];
        });
    }

    /**
     * The abilities an issued token carries, `*` when none are configured.
     *
     * @return list<string>
     */
    private function tokenAbilities(): array
    {
        $abilities = config('uzairports.api.token_abilities', ['*']);

        $abilities = is_array($abilities)
            ? array_values(array_filter($abilities, fn (mixed $ability): bool => is_string($ability) && $ability !== ''))
            : [];

        return $abilities === [] ? ['*'] : $abilities;
    }

    /**
     * When an issued token stops being accepted, from `api.token_expiration`
     * (minutes); null leaves it to Sanctum's own setting.
     */
    private function tokenExpiresAt(): ?CarbonInterface
    {
        $minutes = config('uzairports.api.token_expiration');

        return is_numeric($minutes) && (int) $minutes > 0 ? now()->addMinutes((int) $minutes) : null;
    }

    /**
     * When `sanctum.expiration` retires a token issued without its own expiry,
     * so the client is told either way. Null where nothing retires it.
     */
    private function globalExpiry(NewAccessToken $accessToken): ?CarbonInterface
    {
        $minutes = config('sanctum.expiration');
        $createdAt = $accessToken->accessToken->getAttribute('created_at');

        if (! is_numeric($minutes) || (int) $minutes <= 0 || ! $createdAt instanceof CarbonInterface) {
            return null;
        }

        return $createdAt->copy()->addMinutes((int) $minutes);
    }
}
