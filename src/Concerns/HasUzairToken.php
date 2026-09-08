<?php

namespace Uzairports\Uzairid\Concerns;

use Illuminate\Database\Eloquent\Relations\HasOne;
use Uzairports\Uzairid\Models\OauthToken;

trait HasUzairToken
{
    /**
     * @return HasOne<OauthToken, $this>
     */
    public function token(): HasOne
    {
        return $this->hasOne(OauthToken::class, 'user_id');
    }

    /**
     * Get the current decrypted access token string, if any.
     */
    public function getUzairAccessToken(): ?string
    {
        return $this->token?->access_token;
    }

    /**
     * Determine whether the user is linked to an UzAirports SSO identity.
     */
    public function isUzairUser(): bool
    {
        return ! blank($this->getAttribute('uzair_id'));
    }
}
