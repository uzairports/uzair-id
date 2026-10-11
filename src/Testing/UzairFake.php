<?php

namespace Uzairports\Uzairid\Testing;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Str;
use RuntimeException;
use Stringable;
use Uzairports\Uzairid\Models\OauthToken;
use Uzairports\Uzairid\Uzair;

/**
 * Accounts and logins for an application's test suite.
 *
 * A fake login is a row `uzair.token` accepts for an hour, written for any
 * account and any session id. That is a sign-in for whoever can reach the
 * call, so outside the unit-test environment it refuses rather than writes.
 */
class UzairFake
{
    /**
     * Create an account linked to a made-up UzAirports ID.
     *
     * `uzair_id`, `name` and `email` are filled in when not given; any other
     * attribute is written as passed.
     *
     * @param  array<string, mixed>  $attributes
     *
     * @throws RuntimeException outside the unit-test environment
     */
    public static function user(array $attributes = []): Model
    {
        self::ensureTesting();

        $model = Uzair::userModel();
        $user = new $model;

        $uzairId = self::text($attributes['uzair_id'] ?? $attributes['id'] ?? null) ?? 'fake-uzair-'.Str::random(8);

        $user->forceFill([
            'uzair_id' => $uzairId,
            'name' => self::text($attributes['name'] ?? null) ?? 'Fake User',
            'email' => self::text($attributes['email'] ?? null) ?? $uzairId.'@example.com',
            ...array_diff_key($attributes, ['id' => true, 'uzair_id' => true, 'name' => true, 'email' => true]),
        ])->save();

        return $user;
    }

    /**
     * File a login for the account under a session, with tokens that expire in an hour.
     *
     * Without a session id, the current request's is used, or a random one
     * where the request has no session.
     *
     * @throws RuntimeException outside the unit-test environment
     */
    public static function login(Model $user, ?string $sessionId = null): OauthToken
    {
        self::ensureTesting();

        $request = request();
        $sessionId ??= $request->hasSession() ? $request->session()->getId() : 'fake-session-'.Str::random(16);

        $token = OauthToken::query()
            ->where('user_id', $user->getKey())
            ->where('session_id', $sessionId)
            ->first() ?? new OauthToken;

        $token->forceFill([
            'user_id' => $user->getKey(),
            'session_id' => $sessionId,
            'access_token' => 'fake-access-token',
            'refresh_token' => 'fake-refresh-token',
            'expires_at' => now()->addHour(),
        ])->save();

        return $token;
    }

    /**
     * @throws RuntimeException outside the unit-test environment
     */
    private static function ensureTesting(): void
    {
        if (! app()->runningUnitTests()) {
            throw new RuntimeException('UzairFake writes accounts and logins anyone could use, so it only runs in the testing environment.');
        }
    }

    private static function text(mixed $value): ?string
    {
        return is_scalar($value) || $value instanceof Stringable ? (string) $value : null;
    }
}
