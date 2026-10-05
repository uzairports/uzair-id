<?php

namespace Uzairports\Uzairid\Events;

use Illuminate\Foundation\Events\Dispatchable;
use Illuminate\Queue\SerializesModels;

class UzairBackchannelLoggedOut
{
    use Dispatchable;
    use SerializesModels;

    /**
     * @param  array<array-key, mixed>  $claims
     */
    public function __construct(
        public array $claims,
        public int $endedCount,
    ) {}
}
