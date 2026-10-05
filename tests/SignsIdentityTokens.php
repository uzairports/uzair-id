<?php

namespace Uzairports\Uzairid\Tests;

use Firebase\JWT\JWT;
use RuntimeException;

/**
 * Sign tokens the way UzAirports ID does, with RSA keys kept as fixtures:
 * generating one needs an `openssl.cnf` some environments do not have.
 */
trait SignsIdentityTokens
{
    /**
     * The key set published for a fixture key.
     *
     * @return array{keys: list<array<string, string>>}
     */
    protected function keySet(string $key = 'identity-provider', string $kid = 'key-1'): array
    {
        $details = openssl_pkey_get_details(openssl_pkey_get_private($this->privateKey($key)) ?: throw new RuntimeException("The [{$key}] fixture is not a key."));

        if ($details === false) {
            throw new RuntimeException("The [{$key}] fixture cannot be read.");
        }

        return ['keys' => [[
            'kty' => 'RSA',
            'alg' => 'RS256',
            'use' => 'sig',
            'kid' => $kid,
            'n' => JWT::urlsafeB64Encode($details['rsa']['n']),
            'e' => JWT::urlsafeB64Encode($details['rsa']['e']),
        ]]];
    }

    /**
     * @param  array<string, mixed>  $claims
     */
    protected function signed(array $claims, string $key = 'identity-provider', string $kid = 'key-1'): string
    {
        return JWT::encode($claims, $this->privateKey($key), 'RS256', $kid);
    }

    private function privateKey(string $key): string
    {
        return (string) file_get_contents(__DIR__."/fixtures/{$key}.pem");
    }
}
