<?php

namespace Uzairports\Uzairid\Events;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Foundation\Events\Dispatchable;
use Illuminate\Queue\SerializesModels;
use Laravel\Socialite\Two\User as SocialiteUser;
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
}
