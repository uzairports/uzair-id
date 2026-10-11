<?php

namespace Uzairports\Uzairid\Actions;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\UniqueConstraintViolationException;
use Illuminate\Http\Request;
use Illuminate\Support\Str;
use Laravel\Socialite\Two\User as SocialiteUser;
use RuntimeException;
use Throwable;
use Uzairports\Uzairid\Models\OauthToken;
use Uzairports\Uzairid\Support\TokenExpiry;
use Uzairports\Uzairid\Uzair;

/**
 * Record the grants of a sign-in as one login of the account.
 *
 * A login is filed under the browser session that made it, or under the
 * Sanctum token a mobile client was issued for it. Signing in again under the
 * same one updates the row rather than adding a second.
 */
class RecordLogin
{
    /**
     * Write the login, retrying once if a concurrent sign-in wrote it first.
     *
     * The `(user_id, session_id)` pair refuses the loser of two callbacks
     * finishing on one session; the retry updates the winner's row.
     *
     * @param  Authenticatable&Model  $user
     *
     * @throws Throwable
     */
    public function __invoke(
        Request $request,
        SocialiteUser $uzairUser,
        Authenticatable $user,
        ?string $sessionId,
        int|string|null $accessTokenId = null,
    ): OauthToken {
        try {
            return $this->write($request, $uzairUser, $user, $sessionId, $accessTokenId);
        } catch (UniqueConstraintViolationException) {
            return $this->write($request, $uzairUser, $user, $sessionId, $accessTokenId);
        }
    }

    /**
     * The row is read and overwritten under the same row lock a renewal takes
     * before it persists, so a refresh in flight on this login either lands
     * first and has its grants surrendered here, or sees grants it did not
     * spend and gives up its own. The surrender itself waits for the commit:
     * it is a round trip to the identity provider and holds no lock.
     *
     * @param  Authenticatable&Model  $user
     *
     * @throws RuntimeException when a model listener refused the write
     * @throws Throwable
     */
    private function write(
        Request $request,
        SocialiteUser $uzairUser,
        Authenticatable $user,
        ?string $sessionId,
        int|string|null $accessTokenId,
    ): OauthToken {
        [$token, $replacedAccessToken, $replacedRefreshToken] = (new OauthToken)->getConnection()->transaction(
            fn (): array => $this->store($request, $uzairUser, $user, $sessionId, $accessTokenId)
        );

        $this->surrenderReplacedGrants($uzairUser, $replacedAccessToken, $replacedRefreshToken);

        return $token;
    }

    /**
     * A listener refusing the write — `save()` answering false — means this
     * login must not be recorded, so it fails the sign-in instead of signing a
     * browser in against a row that does not exist.
     *
     * The device columns are written as null, not skipped, while
     * `record_device` is off: the row may hold what an earlier sign-in stored.
     *
     * @param  Authenticatable&Model  $user
     * @return array{OauthToken, ?string, ?string}
     *
     * @throws RuntimeException when a model listener refused the write
     */
    private function store(
        Request $request,
        SocialiteUser $uzairUser,
        Authenticatable $user,
        ?string $sessionId,
        int|string|null $accessTokenId,
    ): array {
        $query = OauthToken::query()->where('user_id', $user->getKey())->lockForUpdate();

        if ($accessTokenId !== null) {
            $token = $query->firstOrNew(['user_id' => $user->getKey(), 'personal_access_token_id' => $accessTokenId]);
        } elseif ($sessionId !== null) {
            $token = $query->firstOrNew(['user_id' => $user->getKey(), 'session_id' => $sessionId]);
        } else {
            $token = $query->whereNull('session_id')->whereNull('personal_access_token_id')->latest('id')->first()
                ?? new OauthToken;
        }

        $replacedAccessToken = $token->exists ? $token->readableAccessToken() : null;
        $replacedRefreshToken = $token->exists ? $token->readableRefreshToken() : null;

        $records = (bool) config('uzairports.record_device', true);
        $rawIp = $request->ip();
        $ip = is_string($rawIp) && $rawIp !== '' ? Str::limit($rawIp, 45, '') : null;

        // Written only under OpenID Connect, whose upgrade migration adds them.
        if (Uzair::oidcEnabled()) {
            $token->forceFill([
                'sid' => $uzairUser->attributes['sid'] ?? null,
                'id_token' => $uzairUser->attributes['id_token'] ?? null,
            ]);
        }

        $saved = $token->forceFill([
            'user_id' => $user->getKey(),
            'session_id' => $sessionId,
            'personal_access_token_id' => $accessTokenId,
            'access_token' => $uzairUser->token,
            'refresh_token' => $uzairUser->refreshToken,
            'expires_at' => TokenExpiry::fromExpiresIn($uzairUser->expiresIn),
            'ip_address' => $records ? $ip : null,
            'user_agent' => $records ? Str::limit((string) $request->userAgent(), 500, '') : null,
        ])->save();

        if (! $saved) {
            throw new RuntimeException('The UzAirports login was refused by a model listener and not recorded.');
        }

        return [$token, $replacedAccessToken, $replacedRefreshToken];
    }

    /**
     * Hand back the grants an overwritten row held.
     *
     * Signing in again under the same session, or again without one, reuses
     * the row; once its grants are overwritten nothing would ever surrender
     * them, and they stayed honored at UzAirports ID. Revocation reports its
     * failures and never raises.
     */
    private function surrenderReplacedGrants(SocialiteUser $uzairUser, ?string $accessToken, ?string $refreshToken): void
    {
        app(EndSessions::class)->surrenderIssued(
            $accessToken !== $uzairUser->token ? $accessToken : null,
            $refreshToken !== $uzairUser->refreshToken ? $refreshToken : null,
        );
    }
}
