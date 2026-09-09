<?php

namespace Uzairports\Uzairid\Concerns;

use Illuminate\Database\Eloquent\Relations\HasMany;
use Illuminate\Database\Eloquent\Relations\HasOne;
use Uzairports\Uzairid\Models\OauthToken;

trait HasUzairToken
{
    /**
     * The login resolved for the session named by `$resolvedForSessionId`.
     *
     * Null is an answer in its own right — this session holds no login — which
     * is why the session it was resolved for is remembered separately.
     */
    protected ?OauthToken $resolvedCurrentToken = null;

    /**
     * The session `$resolvedCurrentToken` was resolved for, or null if none was.
     */
    protected ?string $resolvedForSessionId = null;

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

    /**
     * The login the current session is running on.
     *
     * A request without a session — an API client, a console command — belongs
     * to no browser, so there is no login to hand back.
     *
     * The answer is remembered for the session it was resolved for, so asking
     * twice in one request costs one query. "No login for this session" is
     * remembered too: it is the answer the `uzair.token` middleware acts on,
     * and re-reading it would mean a query on every ask.
     */
    public function currentToken(): ?OauthToken
    {
        $sessionId = $this->currentSessionId();

        if ($sessionId === null) {
            return null;
        }

        if ($this->resolvedForSessionId === $sessionId) {
            return $this->resolvedCurrentToken;
        }

        $this->resolvedCurrentToken = $this->tokens()->firstWhere('session_id', $sessionId);
        $this->resolvedForSessionId = $sessionId;

        return $this->resolvedCurrentToken;
    }

    /**
     * Adopt a login already looked up for the given session.
     *
     * The `uzair.token` middleware resolves the login to decide whether the
     * session may continue and hands the result here so that a controller or a
     * view asking the same question afterward is answered without a second
     * query. Null is adopted as readily as a row: "this session holds no login"
     * is an answer worth keeping.
     */
    public function rememberCurrentToken(?OauthToken $token, string $sessionId): static
    {
        $this->resolvedCurrentToken = $token;
        $this->resolvedForSessionId = $sessionId;

        return $this;
    }

    /**
     * Get the decrypted access token of the current session, if any.
     *
     * A token stored under a key the application no longer holds cannot be read
     * back, and answers null the same way a session holding no login does: in
     * both cases there is no token here to call the identity provider with.
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
        $request = request();

        return $request->hasSession() ? $request->session()->getId() : null;
    }
}
