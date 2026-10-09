<?php

namespace Uzairports\Uzairid\Http\Controllers;

use DomainException;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Log;
use InvalidArgumentException;
use Laravel\Socialite\Facades\Socialite;
use RuntimeException;
use Throwable;
use UnexpectedValueException;
use Uzairports\Uzairid\Actions\EndSessions;
use Uzairports\Uzairid\Actions\VerifyIdentityToken;
use Uzairports\Uzairid\Events\UzairBackchannelLoggedOut;
use Uzairports\Uzairid\Models\OauthToken;
use Uzairports\Uzairid\Socialite\UzairportsProvider;
use Uzairports\Uzairid\Uzair;

/**
 * The endpoint behind `Uzair::backchannelLogoutRoutes()`: UzAirports ID says
 * here that somebody signed out there (OpenID Connect Back-Channel Logout).
 *
 * The provider names the session it ended (`sid`), the account (`sub`), or
 * both, in a logout token it signed. The logins filed under them are ended
 * the way any other is — row, stored session, Sanctum token — and their
 * grants handed back unless `revoke_on_backchannel_logout` is off.
 *
 * A token that cannot be trusted is answered 400; a failure on this side
 * (keys unreachable, misconfiguration) raises, so the provider tries again.
 * OpenID Connect being off is answered 400 and logged instead: retrying
 * cannot fix it.
 */
class UzairBackchannelLogoutController
{
    private const string LOGOUT_EVENT = 'http://schemas.openid.net/event/backchannel-logout';

    /**
     * How long after it was issued a logout token is still accepted, beyond
     * the clock skew. Its `jti` is remembered for as long, so a replayed copy
     * is acknowledged without ending anything again.
     */
    private const int MAX_AGE = 300;

    /**
     * @throws Throwable
     */
    public function __invoke(Request $request, VerifyIdentityToken $verify, EndSessions $endSessions): JsonResponse
    {
        // Without OpenID Connect no login is filed under a `sid`, and the
        // columns may not exist; a 500 would have the provider retry forever.
        if (! Uzair::oidcEnabled()) {
            Log::error('An UzAirports back-channel logout arrived, but [uzairports.oidc.enabled] is off, so no login could be ended.');

            return $this->refuse();
        }

        $logoutToken = $request->input('logout_token');

        if (! is_string($logoutToken) || $logoutToken === '') {
            return $this->refuse();
        }

        try {
            $claims = $verify($logoutToken, $this->provider(), requireExpiry: false);

            $this->ensureIsALogoutToken($claims);
        } catch (UnexpectedValueException|DomainException|InvalidArgumentException $exception) {
            Log::warning('An UzAirports back-channel logout token was refused.', [
                'exception_class' => $exception::class,
                'reason' => $exception->getMessage(),
            ]);

            return $this->refuse();
        }

        if ($this->isARepeat($claims)) {
            return $this->acknowledge();
        }

        try {
            $endedCount = $endSessions->endWhere(
                $this->loginsNamedBy($claims),
                revoke: (bool) config('uzairports.revoke_on_backchannel_logout', true),
            );
        } catch (Throwable $exception) {
            $this->forgetHavingActedOn($claims);

            throw $exception;
        }

        UzairBackchannelLoggedOut::dispatch($claims, $endedCount);

        return $this->acknowledge();
    }

    /**
     * What a logout token must say beyond what every provider token does
     * (OpenID Connect Back-Channel Logout 1.0, §2.6).
     *
     * @param  array<array-key, mixed>  $claims
     *
     * @throws UnexpectedValueException when it is not a logout token
     */
    private function ensureIsALogoutToken(array $claims): void
    {
        $events = $claims['events'] ?? null;

        if (! is_array($events) || ! is_array($events[self::LOGOUT_EVENT] ?? null)) {
            throw new UnexpectedValueException('The token does not announce a back-channel logout.');
        }

        // A nonce marks an ID token, which must never be accepted as one.
        if (array_key_exists('nonce', $claims)) {
            throw new UnexpectedValueException('The token carries a nonce.');
        }

        if ($this->claim($claims, 'sid') === null && $this->claim($claims, 'sub') === null) {
            throw new UnexpectedValueException('The token names neither a session nor an account.');
        }

        if ($this->claim($claims, 'jti') === null) {
            throw new UnexpectedValueException('The token has no jti.');
        }

        $issuedAt = is_numeric($claims['iat'] ?? null) ? (int) $claims['iat'] : 0;

        if ($issuedAt < now()->getTimestamp() - self::MAX_AGE - VerifyIdentityToken::leeway()) {
            throw new UnexpectedValueException('The token is too old.');
        }

        if ($issuedAt > now()->getTimestamp() + VerifyIdentityToken::leeway()) {
            throw new UnexpectedValueException('The token was issued in the future.');
        }
    }

    /**
     * Whether this logout token was already acted on.
     *
     * The provider may deliver one twice; ending the same logins again is
     * harmless, but a copy replayed later must not end logins made since. A
     * cache that cannot answer lets the token through — its age bounds it.
     *
     * @param  array<array-key, mixed>  $claims
     */
    private function isARepeat(array $claims): bool
    {
        try {
            return ! Cache::store()->add($this->repeatKey($claims), true, self::MAX_AGE + 2 * VerifyIdentityToken::leeway());
        } catch (Throwable) {
            return false;
        }
    }

    /**
     * Let the provider's retry of a logout that failed here be acted on.
     *
     * The token is marked before its logins are ended; left marked after a
     * failure, the retry the 500 asks for would be acknowledged as a repeat
     * and end nothing.
     *
     * @param  array<array-key, mixed>  $claims
     */
    private function forgetHavingActedOn(array $claims): void
    {
        try {
            Cache::store()->forget($this->repeatKey($claims));
        } catch (Throwable) {
            // The original failure is the one to report.
        }
    }

    /**
     * @param  array<array-key, mixed>  $claims
     */
    private function repeatKey(array $claims): string
    {
        return 'uzairid:logout-token:'.hash('sha256', (string) $this->claim($claims, 'jti'));
    }

    /**
     * The logins a logout token names: those filed under its `sid`, narrowed
     * to its `sub` when it names one, or every login of the `sub`'s account.
     *
     * @param  array<array-key, mixed>  $claims
     * @return Builder<OauthToken>
     */
    private function loginsNamedBy(array $claims): Builder
    {
        $sid = $this->claim($claims, 'sid');
        $sub = $this->claim($claims, 'sub');
        $accountKeys = $sub !== null ? $this->accountKeysOf((string) $sub) : null;

        return OauthToken::query()
            ->when($sid !== null, fn (Builder $query) => $query->where('sid', $sid))
            ->when($sub !== null, fn (Builder $query) => $query->whereIn('user_id', $accountKeys ?? []));
    }

    /**
     * The keys of the accounts linked to an UzAirports identity.
     *
     * @return list<int|string>
     */
    private function accountKeysOf(string $uzairId): array
    {
        $model = Uzair::userModel();
        $account = new $model;

        /** @var list<int|string> */
        return $account->newQuery()
            ->where('uzair_id', $uzairId)
            ->pluck($account->getKeyName())
            ->all();
    }

    /**
     * A claim that is a non-empty string, or null.
     *
     * @param  array<array-key, mixed>  $claims
     */
    private function claim(array $claims, string $name): ?string
    {
        $value = $claims[$name] ?? null;

        return is_string($value) && $value !== '' ? $value : null;
    }

    /**
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

    private function acknowledge(): JsonResponse
    {
        return new JsonResponse(null, 200, ['Cache-Control' => 'no-store']);
    }

    private function refuse(): JsonResponse
    {
        return new JsonResponse(['error' => 'invalid_request'], 400, ['Cache-Control' => 'no-store']);
    }
}
