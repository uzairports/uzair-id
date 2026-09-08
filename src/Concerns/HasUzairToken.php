<?php

namespace Uzairports\Uzairid\Concerns;

use Illuminate\Database\Eloquent\Relations\HasMany;
use Illuminate\Database\Eloquent\Relations\HasOne;
use Uzairports\Uzairid\Models\OauthToken;

trait HasUzairToken
{
    /**
     * Every SSO login the account currently holds — one per browser session.
     *
     * @return HasMany<OauthToken, $this>
     */
    public function tokens(): HasMany
    {
        return $this->hasMany(OauthToken::class, 'user_id');
    }

    /**
     * The most recent login, whichever device made it.
     *
     * Useful for showing something about the account, never for acting on
     * behalf of the person in front of you: on a second device this is somebody
     * else's browser. Reach for `currentToken()` when you mean "this request".
     *
     * @return HasOne<OauthToken, $this>
     */
    public function token(): HasOne
    {
        return $this->hasOne(OauthToken::class, 'user_id')->latestOfMany();
    }

    protected ?OauthToken $resolvedCurrentToken = null;

    protected bool $hasResolvedCurrentToken = false;

    /**
     * The login the current session is running on.
     *
     * A request without a session — an API client, a console command — belongs
     * to no browser, so there is no login to hand back.
     */
    public function currentToken(): ?OauthToken
    {
        $sessionId = $this->currentSessionId();

        if ($sessionId === null) {
            return null;
        }

        if ($this->hasResolvedCurrentToken && $this->resolvedCurrentToken?->session_id === $sessionId) {
            return $this->resolvedCurrentToken;
        }

        $this->resolvedCurrentToken = $this->tokens()->firstWhere('session_id', $sessionId);
        $this->hasResolvedCurrentToken = true;

        return $this->resolvedCurrentToken;
    }

    /**
     * Get the decrypted access token of the current session, if any.
     */
    public function getUzairAccessToken(): ?string
    {
        return $this->currentToken()?->access_token;
    }

    /**
     * Determine whether the user is linked to an UzAirports SSO identity.
     */
    public function isUzairUser(): bool
    {
        return ! blank($this->getAttribute('uzair_id'));
    }

    private function currentSessionId(): ?string
    {
        $request = request();

        return $request->hasSession() ? $request->session()->getId() : null;
    }
}
