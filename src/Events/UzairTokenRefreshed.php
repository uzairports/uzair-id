<?php

namespace Uzairports\Uzairid\Events;

use Illuminate\Foundation\Events\Dispatchable;
use Illuminate\Queue\SerializesModels;
use Uzairports\Uzairid\Models\OauthToken;

class UzairTokenRefreshed
{
    use Dispatchable;
    use SerializesModels;

    public function __construct(public OauthToken $token) {}
}
