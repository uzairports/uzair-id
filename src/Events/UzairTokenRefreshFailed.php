<?php

namespace Uzairports\Uzairid\Events;

use Illuminate\Foundation\Events\Dispatchable;
use Illuminate\Queue\SerializesModels;
use Throwable;
use Uzairports\Uzairid\Models\OauthToken;

class UzairTokenRefreshFailed
{
    use Dispatchable;
    use SerializesModels;

    public function __construct(
        public OauthToken $token,
        public ?Throwable $exception = null,
    ) {}
}
