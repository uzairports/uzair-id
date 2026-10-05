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
     * Keep the grants out of the serialized event.
     *
     * Queued listeners serialize the event into an unencrypted queue store.
     * Models go in as identifiers, but `$socialiteUser` would carry the access
     * and refresh tokens in plain text, so the serialized copy has them
     * stripped. The live instance is untouched for synchronous listeners; a
     * queued listener reads the grant off `$token`.
     */
    protected function getPropertyValue(ReflectionProperty $property): mixed
    {
        $value = $property->getValue($this);

        return $value instanceof SocialiteUser
            ? self::withoutGrants($value)
            : $value;
    }

    /**
     * A clone of the identity with both tokens emptied. Cloned so the
     * dispatcher's object is unchanged; emptied rather than nulled because
     * Socialite types both as strings. The raw profile holds no credential.
     */
    private static function withoutGrants(SocialiteUser $identity): SocialiteUser
    {
        $stripped = clone $identity;

        $stripped->token = '';
        $stripped->refreshToken = '';
        $stripped->attributes = array_diff_key($stripped->attributes, ['id_token' => true]);

        return $stripped;
    }
}
