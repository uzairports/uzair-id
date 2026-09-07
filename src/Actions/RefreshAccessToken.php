<?php

namespace Uzairports\Uzairid\Actions;

use Illuminate\Support\Facades\Log;
use Laravel\Socialite\Facades\Socialite;
use Throwable;
use Uzairports\Uzairid\Models\OauthToken;
use Uzairports\Uzairid\Socialite\UzairportsProvider;

class RefreshAccessToken
{
    /**
     * Exchange the stored refresh token for a fresh access token.
     *
     * Returns false when the SSO server refuses the exchange, in which case the
     * user has to authenticate again.
     */
    public function __invoke(OauthToken $token): bool
    {
        if (blank($token->refresh_token)) {
            return false;
        }

        try {
            /** @var UzairportsProvider $provider */
            $provider = Socialite::driver('uzairports');

            $refreshed = $provider->refreshToken($token->refresh_token);
        } catch (Throwable $e) {
            Log::warning('Failed to refresh UzAirports access token: '.$e->getMessage(), [
                'user_id' => $token->user_id,
            ]);

            return false;
        }

        $token->forceFill([
            'access_token' => $refreshed->token,
            'refresh_token' => $refreshed->refreshToken ?: $token->refresh_token,
            'expires_in' => $refreshed->expiresIn,
            'expires_at' => now()->addSeconds((int) $refreshed->expiresIn),
        ])->save();

        return true;
    }
}
