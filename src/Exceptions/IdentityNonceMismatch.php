<?php

namespace Uzairports\Uzairid\Exceptions;

use RuntimeException;

/**
 * The ID token's `nonce` names no handshake this session started.
 *
 * A `RuntimeException`, as the failure was raised before it had a type of its
 * own, so code catching that keeps catching it. The callback tells it apart
 * by type and answers it as a lost handshake, like a missing `state`.
 */
class IdentityNonceMismatch extends RuntimeException
{
    public static function make(): self
    {
        return new self('The UzAirports ID token nonce is missing or does not match the session nonce.');
    }
}
