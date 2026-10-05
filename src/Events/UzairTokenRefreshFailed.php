<?php

namespace Uzairports\Uzairid\Events;

use Illuminate\Foundation\Events\Dispatchable;
use Illuminate\Queue\SerializesModels;
use ReflectionProperty;
use Throwable;
use Uzairports\Uzairid\Models\OauthToken;

class UzairTokenRefreshFailed
{
    use Dispatchable;
    use SerializesModels;

    /**
     * The class of `$exception`, which survives being queued when it does not.
     */
    public ?string $exceptionClass;

    public function __construct(
        public OauthToken $token,
        public ?Throwable $exception = null,
    ) {
        $this->exceptionClass = $exception !== null ? $exception::class : null;
    }

    /**
     * Leave the exception out when the event is serialized for a queued listener.
     *
     * An exception is not serializable in general — a Guzzle one holds PSR-7
     * streams — and the event is serialized inside `dispatch()`, so a queued
     * listener would make the dispatch throw on the refresh path and keep a
     * refused login from being ended.
     */
    protected function getPropertyValue(ReflectionProperty $property): mixed
    {
        $value = $property->getValue($this);

        return $value instanceof Throwable ? null : $value;
    }
}
