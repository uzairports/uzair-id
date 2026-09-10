<?php

namespace Uzairports\Uzairid\Concerns;

use Illuminate\Database\Eloquent\Relations\HasMany;
use Illuminate\Database\Eloquent\Relations\HasOne;
use Uzairports\Uzairid\Models\OauthToken;

/**
 * The SSO identity behind an account, and the logins it holds.
 *
 * `uzair_id` is declared here rather than left to each host application to
 * declare for itself: the package's own migration adds the column, this trait
 * reads it in `isUzairUser()`, and the middleware reads it to decide whether a
 * session that lost its login belongs to SSO at all. A model carrying the trait
 * therefore carries the column, and static analysis in every application using
 * it was reporting an undefined property on a column the package put there.
 *
 * @property string|null $uzair_id
 */
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
     * The session `$resolvedCurrentToken` was resolved for.
     *
     * Null is a session id in its own right here — it stands for a caller that
     * has no browser session — so it cannot also mean "nothing resolved yet".
     * That is what `$currentTokenWasResolved` is for.
     */
    protected ?string $resolvedForSessionId = null;

    /**
     * Whether anything has been resolved to compare `$resolvedForSessionId` to.
     */
    protected bool $currentTokenWasResolved = false;

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
     * The login this request is running on.
     *
     * A request that has a browser session is answered by the login naming it.
     * One that has none — an API client, a console command — is answered by a
     * login that names none either: `session_id` is nullable precisely so that
     * a token can be held outside a session, and such a row belongs to the
     * caller as surely as a browser's row belongs to its browser.
     *
     * It used to answer null there, and had to. A sessionless request was being
     * handed the account's most recent login — somebody else's browser — so
     * refusing to give it out was the only thing keeping this method honest.
     * `uzair.token` stopped doing that; the row it resolves now is the caller's
     * own, and this went on refusing to hand back a login the middleware had
     * just checked. An application following the README's own advice for API
     * routes had no supported way to read its token.
     *
     * The answer is remembered for the session it was resolved for, so asking
     * twice in one request costs one query. "No login here" is remembered too:
     * it is the answer the middleware acts on, and re-reading it would mean a
     * query on every ask.
     *
     * The unique pair does not collapse several null session ids, so the most
     * recent of them is taken — the same rule `uzair.token` goes by.
     */
    public function currentToken(): ?OauthToken
    {
        $sessionId = $this->currentSessionId();

        if ($this->currentTokenWasResolved && $this->resolvedForSessionId === $sessionId) {
            return $this->resolvedCurrentToken;
        }

        $token = $sessionId === null
            ? $this->tokens()->whereNull('session_id')->latest('id')->first()
            : $this->tokens()->firstWhere('session_id', $sessionId);

        $this->rememberCurrentToken($token, $sessionId);

        return $token;
    }

    /**
     * Adopt a login already looked up for the given session.
     *
     * The `uzair.token` middleware resolves the login to decide whether the
     * request may continue and hands the result here so that a controller or a
     * view asking the same question afterward is answered without a second
     * query. Null is adopted as readily as a row: "this caller holds no login"
     * is an answer worth keeping.
     *
     * A null session id is passed and kept, rather than refused: it is what the
     * middleware resolved a sessionless request against, and dropping it here
     * was what made an API client pay a query for a lookup already made.
     */
    public function rememberCurrentToken(?OauthToken $token, ?string $sessionId): static
    {
        $this->resolvedCurrentToken = $token;
        $this->resolvedForSessionId = $sessionId;
        $this->currentTokenWasResolved = true;

        return $this;
    }

    /**
     * Get the decrypted access token of the current login, if there is one.
     *
     * A token stored under a key the application no longer holds cannot be read
     * back, and answers null the same way a caller holding no login does: in
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
