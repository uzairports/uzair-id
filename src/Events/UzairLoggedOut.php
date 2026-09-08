<?php

namespace Uzairports\Uzairid\Events;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Foundation\Events\Dispatchable;
use Illuminate\Queue\SerializesModels;

class UzairLoggedOut
{
    use Dispatchable;
    use SerializesModels;

    public function __construct(
        public ?Model $user = null,
    ) {}
}
