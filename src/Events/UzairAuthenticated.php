<?php

namespace Uzairports\Uzairid\Events;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Foundation\Events\Dispatchable;
use Illuminate\Queue\SerializesModels;
use Laravel\Socialite\Two\User as SocialiteUser;
use ReflectionProperty;
use Uzairports\Uzairid\Models\OauthToken;

class UzairAuthenticated
{
    use Dispatchable;
    use SerializesModels;

    public function __construct(
        public Model $user,
        public SocialiteUser $socialiteUser,
        public ?OauthToken $token = null,
    ) {}

    /**
     * Keep the grants out of anything this event is written into.
     *
     * A listener that implements `ShouldQueue` has the event serialized into
     * the queue payload at dispatch — a row in `jobs`, a string in Redis, a
     * line in whatever a failed job is recorded in. `SerializesModels` puts
     * `$user` and `$token` in as identifiers, so both come back out of the
     * database, and the two token columns come back through their `encrypted`
     * casts. `$socialiteUser` is not a model, and went in whole: the access
     * token and the rotating refresh token the handshake had just been issued,
     * spelled out beside the profile, in a store nothing in this package
     * encrypts.
     *
     * This is the hook `SerializesModels` reads every property through, so the
     * copy that goes in carries the profile and not the grants. The instance
     * itself is left alone — a synchronous listener running after a queued one
     * still reads the token it was dispatched with, and only what leaves the
     * process is stripped.
     *
     * A queued listener that needs the grant reads it off `$token`, which is
     * the login's own row and the one place the package keeps it.
     */
    protected function getPropertyValue(ReflectionProperty $property): mixed
    {
        $value = $property->getValue($this);

        return $value instanceof SocialiteUser
            ? self::withoutGrants($value)
            : $value;
    }

    /**
     * The same identity with nothing spendable left on it.
     *
     * Cloned rather than emptied in place: the object belongs to the request
     * that dispatched the event, and listeners after this one are entitled to
     * find it as it was. The raw profile is left as it is — `mapUserToObject()`
     * fills it from the userinfo response, which carries no credential.
     *
     * Emptied rather than nulled, because Socialite types both as strings and a
     * listener restored from a payload should find the type its own analysis
     * was written against. `filled()` reads the two the same way.
     */
    private static function withoutGrants(SocialiteUser $identity): SocialiteUser
    {
        $stripped = clone $identity;

        $stripped->token = '';
        $stripped->refreshToken = '';

        return $stripped;
    }
}
