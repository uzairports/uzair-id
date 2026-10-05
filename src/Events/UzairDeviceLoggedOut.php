<?php

namespace Uzairports\Uzairid\Events;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Foundation\Events\Dispatchable;
use Illuminate\Queue\SerializesModels;
use Uzairports\Uzairid\Models\OauthToken;

class UzairDeviceLoggedOut
{
    use Dispatchable;
    use SerializesModels;

    public function __construct(
        public ?Model $user,
        public OauthToken $token,
    ) {}
}
