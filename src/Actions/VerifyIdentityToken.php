<?php

namespace Uzairports\Uzairid\Actions;

use Firebase\JWT\JWK;
use Firebase\JWT\JWT;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Log;
use Throwable;
use UnexpectedValueException;
use Uzairports\Uzairid\Socialite\UzairportsProvider;

/**
 * Verify a JWT the identity provider signed: an ID token, or the logout token
 * of a back-channel logout.
 *
 * The signature is checked against the provider's published keys, with the
 * algorithms `oidc.algorithms` allows (RS256 by default, and never an HMAC one,
 * so a token cannot pick a weaker algorithm), then the claims every
 * such token carries: `iss` is the provider, `aud` is this client, and `iat`
 * and `exp` are within the configured clock skew. What a particular kind of
 * token must say beyond that is its caller's to check.
 */
class VerifyIdentityToken
{
    /**
     * `$types` names the JOSE `typ` values the caller accepts. A token that
     * declares another is refused — an access token (`at+jwt`) must not pass
     * for a logout token because it is signed by the same keys. A token that
     * declares none is let through, since providers commonly omit it.
     *
     * @param  list<string>|null  $types  null accepts any
     * @return array<array-key, mixed> the token's claims
     *
     * @throws Throwable when the token cannot be trusted or the keys cannot be read
     */
    public function __invoke(string $jwt, UzairportsProvider $provider, ?array $types = null): array
    {
        $claims = $this->decode($jwt, $provider);

        if ($types !== null && ! $this->declaresOneOf($jwt, $types)) {
            throw new UnexpectedValueException('An UzAirports token declares a type this endpoint does not accept.');
        }

        if (($claims['iss'] ?? null) !== $provider->issuer()) {
            throw new UnexpectedValueException('An UzAirports token was issued by somebody else.');
        }

        if (! $this->isForThisClient($claims, $provider->getClientId())) {
            throw new UnexpectedValueException('An UzAirports token was issued to another client.');
        }

        if (! is_numeric($claims['iat'] ?? null) || ! is_numeric($claims['exp'] ?? null)) {
            throw new UnexpectedValueException('An UzAirports token does not say when it was issued or until when it holds.');
        }

        return $claims;
    }

    /**
     * Whether the token's `typ` header is absent or one of `$types`.
     *
     * Read after the signature is checked, which covers the header too. The
     * `application/` prefix is optional and the comparison ignores case (RFC
     * 7515 §4.1.9).
     *
     * @param  list<string>  $types
     */
    private function declaresOneOf(string $jwt, array $types): bool
    {
        $header = json_decode(JWT::urlsafeB64Decode(explode('.', $jwt)[0]), true);
        $type = is_array($header) ? ($header['typ'] ?? null) : null;

        if ($type === null) {
            return true;
        }

        if (! is_string($type)) {
            return false;
        }

        $normalize = fn (string $value): string => strtolower(preg_replace('#^application/#i', '', $value) ?? $value);

        return in_array($normalize($type), array_map($normalize, $types), true);
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
     * The algorithms the provider may sign with, mapped to the key type each needs.
     *
     * Only asymmetric ones: the keys are read from a public endpoint, and an
     * HMAC algorithm would verify against a key anyone can download — a token
     * signed with the published key itself would pass.
     *
     * @var array<string, string>
     */
    private const array ASYMMETRIC_ALGORITHMS = [
        'RS256' => 'RSA',
        'RS384' => 'RSA',
        'RS512' => 'RSA',
        'PS256' => 'RSA',
        'ES256' => 'EC',
        'ES384' => 'EC',
        'ES256K' => 'EC',
        'EdDSA' => 'OKP',
    ];

    /**
     * The algorithms allowed when verifying ID and logout tokens.
     *
     * `oidc.algorithms` narrows the asymmetric ones above and cannot widen
     * them: anything else it names is dropped and reported, and a setting left
     * with nothing allowed falls back to RS256.
     *
     * @phpstan-impure
     *
     * @return list<string>
     */
    public static function allowedAlgorithms(): array
    {
        $algorithms = config('uzairports.oidc.algorithms', ['RS256']);
        $algorithms = is_array($algorithms) ? array_values(array_filter($algorithms, is_string(...))) : [];

        $allowed = array_values(array_filter(
            $algorithms,
            fn (string $algorithm): bool => isset(self::ASYMMETRIC_ALGORITHMS[$algorithm], JWT::$supported_algs[$algorithm]),
        ));

        $refused = array_values(array_diff($algorithms, $allowed, ['']));

        if ($refused !== []) {
            Log::warning('UzAirports ID tokens are only verified with asymmetric algorithms; the rest of oidc.algorithms is ignored.', [
                'ignored' => $refused,
            ]);
        }

        return $allowed === [] ? ['RS256'] : $allowed;
    }

    /**
     * @param  array<array-key, mixed>  $jwks
     * @return array<array-key, mixed>
     */
    private function decodeWith(string $jwt, array $jwks): array
    {
        $usable = $this->usableKeys($jwks, self::allowedAlgorithms());

        if ($usable['keys'] === []) {
            throw new UnexpectedValueException('The UzAirports signing keys include no keys with an allowed algorithm.');
        }

        $keys = JWK::parseKeySet($usable);

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
     * The keys of the set that may verify a token, each naming its algorithm.
     *
     * A key that names none is given the first allowed algorithm its own type
     * can sign with, rather than the first allowed one outright: an RSA key
     * labelled ES256 verifies nothing, and every token then fails. A key no
     * allowed algorithm fits is left out before the library parses it, so a
     * key of a type it cannot read does not take the whole set down with it.
     *
     * @param  array<array-key, mixed>  $jwks
     * @param  list<string>  $allowed
     * @return array{keys: list<array<array-key, mixed>>}
     */
    private function usableKeys(array $jwks, array $allowed): array
    {
        $usable = [];

        foreach (is_array($jwks['keys'] ?? null) ? $jwks['keys'] : [] as $key) {
            if (! is_array($key)) {
                continue;
            }

            $algorithm = $key['alg'] ?? null;

            if ($algorithm === null) {
                $type = $key['kty'] ?? null;
                $algorithm = array_find($allowed, fn (string $candidate): bool => self::ASYMMETRIC_ALGORITHMS[$candidate] === $type);
            }

            if (is_string($algorithm) && in_array($algorithm, $allowed, true)) {
                $usable[] = ['alg' => $algorithm] + $key;
            }
        }

        return ['keys' => $usable];
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
