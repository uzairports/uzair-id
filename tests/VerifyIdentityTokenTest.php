<?php

namespace Uzairports\Uzairid\Tests;

use Illuminate\Cache\Events\CacheHit;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Event;
use Mockery;
use Mockery\MockInterface;
use UnexpectedValueException;
use Uzairports\Uzairid\Actions\VerifyIdentityToken;
use Uzairports\Uzairid\Socialite\UzairportsProvider;

class VerifyIdentityTokenTest extends TestCase
{
    use SignsIdentityTokens;

    private const string JWKS_URL = 'https://sso.test/.well-known/jwks.json';

    /**
     * A key id the cached set does not hold is the provider rotating its keys.
     */
    public function test_an_unknown_key_id_fetches_the_set_again(): void
    {
        $this->cacheKeySet(self::JWKS_URL, $this->keySet('identity-provider', 'key-1'));

        $provider = $this->provider(self::JWKS_URL);
        $provider->shouldReceive('jwks')->once()->andReturn($this->keySet('impostor', 'key-2'));

        $claims = (new VerifyIdentityToken)($this->signed($this->claims(), 'impostor', 'key-2'), $provider);

        $this->assertSame('42', $claims['sub']);
    }

    /**
     * The refetch is throttled per key set URL: one provider rotating its
     * keys does not use up the minute of another.
     */
    public function test_the_refetch_throttle_is_kept_per_key_set_url(): void
    {
        $otherUrl = 'https://other-sso.test/jwks';

        $this->cacheKeySet(self::JWKS_URL, $this->keySet('identity-provider', 'key-1'));
        $this->cacheKeySet($otherUrl, $this->keySet('identity-provider', 'key-1'));

        $first = $this->provider(self::JWKS_URL);
        $first->shouldReceive('jwks')->once()->andReturn($this->keySet('impostor', 'key-2'));

        $second = $this->provider($otherUrl);
        $second->shouldReceive('jwks')->once()->andReturn($this->keySet('impostor', 'key-2'));

        $jwt = $this->signed($this->claims(), 'impostor', 'key-2');

        (new VerifyIdentityToken)($jwt, $first);
        $claims = (new VerifyIdentityToken)($jwt, $second);

        $this->assertSame('42', $claims['sub']);
    }

    /**
     * A process that loses the refetch to another reads the set the winner
     * stored rather than refusing a token it could have verified.
     */
    public function test_losing_the_refetch_reads_the_cache_again(): void
    {
        $key = 'uzairid:jwks:'.hash('sha256', self::JWKS_URL);

        $this->cacheKeySet(self::JWKS_URL, $this->keySet('identity-provider', 'key-1'));
        Cache::add('uzairid:jwks-refetched:'.hash('sha256', self::JWKS_URL), true, 60);

        // The winner stores the rotated set just after this process read the
        // old one.
        $rotated = $this->keySet('impostor', 'key-2');
        $stored = false;
        Event::listen(CacheHit::class, function (CacheHit $event) use ($key, $rotated, &$stored): void {
            if ($event->key === $key && ! $stored) {
                $stored = true;
                Cache::put($key, $rotated, 3600);
            }
        });

        $provider = $this->provider(self::JWKS_URL);
        $provider->shouldNotReceive('jwks');

        $claims = (new VerifyIdentityToken)($this->signed($this->claims(), 'impostor', 'key-2'), $provider);

        $this->assertSame('42', $claims['sub']);
    }

    /**
     * A key the set already holds is not a rotation: a token whose signature
     * fails under it must not cost the provider a request.
     */
    public function test_a_bad_signature_under_a_known_key_does_not_fetch_the_set_again(): void
    {
        $this->cacheKeySet(self::JWKS_URL, $this->keySet('identity-provider', 'key-1'));

        $provider = $this->provider(self::JWKS_URL);
        $provider->shouldNotReceive('jwks');

        $this->expectException(UnexpectedValueException::class);

        (new VerifyIdentityToken)($this->signed($this->claims(), 'impostor', 'key-1'), $provider);
    }

    /**
     * @param  array<array-key, mixed>  $jwks
     */
    private function cacheKeySet(string $url, array $jwks): void
    {
        Cache::put('uzairid:jwks:'.hash('sha256', $url), $jwks, 3600);
    }

    private function provider(string $jwksUrl): UzairportsProvider&MockInterface
    {
        /** @var UzairportsProvider&MockInterface $provider */
        $provider = Mockery::mock(UzairportsProvider::class);
        $provider->shouldReceive('jwksUrl')->andReturn($jwksUrl);
        $provider->shouldReceive('issuer')->andReturn('https://sso.test');
        $provider->shouldReceive('getClientId')->andReturn('test-client');

        return $provider;
    }

    /**
     * @return array<string, mixed>
     */
    private function claims(): array
    {
        return [
            'iss' => 'https://sso.test',
            'aud' => 'test-client',
            'sub' => '42',
            'iat' => time(),
            'exp' => time() + 300,
        ];
    }
}
