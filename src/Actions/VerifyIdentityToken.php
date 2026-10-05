<?php

namespace Uzairports\Uzairid\Actions;

use Firebase\JWT\JWK;
use Firebase\JWT\JWT;
use Illuminate\Support\Facades\Cache;
use Throwable;
use UnexpectedValueException;
use Uzairports\Uzairid\Socialite\UzairportsProvider;

/**
 * Verify a JWT the identity provider signed: an ID token, or the logout token
 * of a back-channel logout.
 *
 * The signature is checked against the provider's published keys (RS256
 * only, so a token cannot pick a weaker algorithm), then the claims every
 * such token carries: `iss` is the provider, `aud` is this client, and `iat`
 * and `exp` are within the configured clock skew. What a particular kind of
 * token must say beyond that is its caller's to check.
 */
class VerifyIdentityToken
{
    /**
     * @return array<array-key, mixed> the token's claims
     *
     * @throws Throwable when the token cannot be trusted or the keys cannot be read
     */
    public function __invoke(string $jwt, UzairportsProvider $provider, bool $requireExpiry = true): array
    {
        $claims = $this->decode($jwt, $provider);

        if (($claims['iss'] ?? null) !== $provider->issuer()) {
            throw new UnexpectedValueException('An UzAirports token was issued by somebody else.');
        }

        if (! $this->isForThisClient($claims, $provider->getClientId())) {
            throw new UnexpectedValueException('An UzAirports token was issued to another client.');
        }

        if (! is_numeric($claims['iat'] ?? null) || ($requireExpiry && ! is_numeric($claims['exp'] ?? null))) {
            throw new UnexpectedValueException('An UzAirports token does not say when it was issued or until when it holds.');
        }

        return $claims;
    }

    /**
     * Seconds of clock skew allowed when reading `iat` and `exp`.
     */
    public static function leeway(): int
    {
        $leeway = config('uzairports.oidc.leeway', 60);

        return max(is_numeric($leeway) ? (int) $leeway : 60, 0);
    }

    /**
     * Check the signature and the token's lifetime.
     *
     * A key id the cached set does not hold is the provider rotating its keys,
     * so the set is fetched once more — at most once a minute, or every forged
     * token naming an unknown key would cost the provider a request.
     *
     * @return array<array-key, mixed>
     */
    private function decode(string $jwt, UzairportsProvider $provider): array
    {
        try {
            return $this->decodeWith($jwt, $this->keys($provider, fresh: false));
        } catch (UnexpectedValueException $exception) {
            if (! str_contains($exception->getMessage(), '"kid"') || ! $this->mayFetchKeysAgain()) {
                throw $exception;
            }
        }

        return $this->decodeWith($jwt, $this->keys($provider, fresh: true));
    }

    /**
     * The algorithms allowed when verifying ID tokens.
     *
     * @return list<string>
     */
    public static function allowedAlgorithms(): array
    {
        $algorithms = config('uzairports.oidc.algorithms', ['RS256']);

        if (! is_array($algorithms) || empty($algorithms)) {
            return ['RS256'];
        }

        /** @var list<string> $filtered */
        $filtered = array_values(array_filter($algorithms, fn (mixed $algo): bool => is_string($algo) && $algo !== ''));

        return $filtered === [] ? ['RS256'] : $filtered;
    }

    /**
     * @param  array<array-key, mixed>  $jwks
     * @return array<array-key, mixed>
     */
    private function decodeWith(string $jwt, array $jwks): array
    {
        $allowed = self::allowedAlgorithms();
        $defaultAlg = $allowed[0] ?? 'RS256';
        $keys = JWK::parseKeySet($jwks, $defaultAlg);

        foreach ($keys as $key) {
            if (! in_array($key->getAlgorithm(), $allowed, true)) {
                throw new UnexpectedValueException("The UzAirports signing keys include an algorithm [{$key->getAlgorithm()}] that is not allowed.");
            }
        }

        // The library reads its clock and skew from statics; both are put back.
        $leeway = JWT::$leeway;
        $timestamp = JWT::$timestamp;

        try {
            JWT::$leeway = self::leeway();
            JWT::$timestamp = now()->getTimestamp();

            $claims = json_decode((string) json_encode(JWT::decode($jwt, $keys)), true);
        } finally {
            JWT::$leeway = $leeway;
            JWT::$timestamp = $timestamp;
        }

        if (! is_array($claims)) {
            throw new UnexpectedValueException('An UzAirports token carries no claims.');
        }

        return $claims;
    }

    /**
     * The provider's key set, from the cache unless a fresh one is asked for.
     *
     * @return array<array-key, mixed>
     */
    private function keys(UzairportsProvider $provider, bool $fresh): array
    {
        $ttl = config('uzairports.oidc.jwks_cache_ttl', 3600);
        $ttl = is_numeric($ttl) ? (int) $ttl : 3600;
        $key = 'uzairid:jwks:'.hash('sha256', $provider->jwksUrl());

        if ($ttl <= 0) {
            return $provider->jwks();
        }

        try {
            if (! $fresh) {
                $cached = Cache::store()->get($key);

                if (is_array($cached)) {
                    return $cached;
                }
            }
        } catch (Throwable) {
            // An unreachable cache costs a fetch, never a sign-in.
        }

        $jwks = $provider->jwks();

        try {
            Cache::store()->put($key, $jwks, $ttl);
        } catch (Throwable) {
            // The next token fetches the keys again.
        }

        return $jwks;
    }

    private function mayFetchKeysAgain(): bool
    {
        try {
            return Cache::store()->add('uzairid:jwks-refetched', true, 60);
        } catch (Throwable) {
            return false;
        }
    }

    /**
     * Whether `aud` names this client, and `azp` does too where it names others.
     *
     * @param  array<array-key, mixed>  $claims
     */
    private function isForThisClient(array $claims, string $clientId): bool
    {
        if ($clientId === '') {
            return false;
        }

        $audience = $claims['aud'] ?? null;

        if (is_string($audience)) {
            return $audience === $clientId;
        }

        if (! is_array($audience) || ! in_array($clientId, $audience, true)) {
            return false;
        }

        return count($audience) === 1 || ($claims['azp'] ?? null) === $clientId;
    }
}
