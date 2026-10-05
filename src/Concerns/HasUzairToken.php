<?php

namespace Uzairports\Uzairid\Concerns;

use Illuminate\Database\Eloquent\Relations\HasMany;
use Illuminate\Database\Eloquent\Relations\HasOne;
use Uzairports\Uzairid\Actions\EnsureTokenStorageMatchesProvider;
use Uzairports\Uzairid\Models\OauthToken;
use Uzairports\Uzairid\Uzair;

/**
 * The SSO identity behind an account, and the logins it holds.
 *
 * `uzair_id` is declared here because the package's migration adds the column
 * and the package reads it, so every model carrying the trait carries it.
 *
 * @property string|null $uzair_id
 */
trait HasUzairToken
{
    /**
     * The login resolved for `$resolvedForSessionId`; null means "no login".
     */
    protected ?OauthToken $resolvedCurrentToken = null;

    /**
     * The session `$resolvedCurrentToken` was resolved for.
     *
     * Null stands for a sessionless caller, so "nothing resolved yet" is
     * tracked by `$currentTokenWasResolved` instead.
     */
    protected ?string $resolvedForSessionId = null;

    /**
     * Whether anything has been resolved to compare `$resolvedForSessionId` to.
     */
    protected bool $currentTokenWasResolved = false;

    /**
     * The Sanctum token `$resolvedCurrentToken` was resolved for, if any.
     */
    protected int|string|null $resolvedForAccessTokenId = null;

    /**
     * Every SSO login the account currently holds, one per session or client.
     *
     * The trait uses this name rather than `tokens()`, which Sanctum's
     * `HasApiTokens` also declares. A model carrying both keeps Sanctum's:
     *
     * ```php
     * use HasApiTokens, HasUzairToken {
     *     HasApiTokens::tokens insteadof HasUzairToken;
     * }
     * ```
     *
     * @return HasMany<OauthToken, $this>
     */
    public function uzairTokens(): HasMany
    {
        return $this->hasMany(OauthToken::class, 'user_id');
    }

    /**
     * Alias of `uzairTokens()` for models without Sanctum.
     *
     * @return HasMany<OauthToken, $this>
     */
    public function tokens(): HasMany
    {
        return $this->uzairTokens();
    }

    /**
     * The most recent login, whichever device made it.
     *
     * For display only: it may belong to another device. Use `currentToken()`
     * to act for this request.
     *
     * @return HasOne<OauthToken, $this>
     */
    public function token(): HasOne
    {
        return $this->hasOne(OauthToken::class, 'user_id')->latestOfMany();
    }

    /**
     * The login this request is running on.
     *
     * Resolved by `OauthToken::scopeHeldBy()`, the same rule `uzair.token`
     * uses: a mobile client by its Sanctum token, a browser by its session, a
     * sessionless caller by a login naming neither.
     *
     * The answer, including "no login", is memoized per session and Sanctum
     * token, so repeated calls in one request cost one query.
     */
    public function currentToken(): ?OauthToken
    {
        app(EnsureTokenStorageMatchesProvider::class)->forUser($this);

        $sessionId = $this->currentSessionId();
        $accessTokenId = Uzair::accessTokenId($this);

        if ($this->currentTokenWasResolved
            && $this->resolvedForSessionId === $sessionId
            && $this->resolvedForAccessTokenId === $accessTokenId) {
            return $this->resolvedCurrentToken;
        }

        /** @var OauthToken|null $token */
        $token = $this->uzairTokens()->heldBy($sessionId, $accessTokenId)->first();

        $this->rememberCurrentToken($token, $sessionId, $accessTokenId);

        return $token;
    }

    /**
     * Adopt a login already looked up for the given session.
     *
     * Called by `uzair.token` so later `currentToken()` calls need no query.
     * A null token and a null session id (a sessionless caller) are both kept
     * as valid answers.
     */
    public function rememberCurrentToken(?OauthToken $token, ?string $sessionId, int|string|null $accessTokenId = null): static
    {
        $this->resolvedCurrentToken = $token;
        $this->resolvedForSessionId = $sessionId;
        $this->resolvedForAccessTokenId = $accessTokenId;
        $this->currentTokenWasResolved = true;

        return $this;
    }

    /**
     * Get the decrypted access token of the current login, if there is one.
     *
     * Null also when the stored token cannot be decrypted.
     */
    public function getUzairAccessToken(): ?string
    {
        return $this->currentToken()?->readableAccessToken();
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
        if (! app()->bound('request')) {
            return null;
        }

        $request = request();

        return $request->hasSession() ? $request->session()->getId() : null;
    }
}
