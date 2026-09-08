<?php

namespace Uzairports\Uzairid\Tests;

use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Psr7\Response;
use Illuminate\Http\Request;
use Laravel\Socialite\Facades\Socialite;
use RuntimeException;
use Uzairports\Uzairid\Socialite\UzairportsProvider;

class UzairportsProviderTest extends TestCase
{
    public function test_provider_generates_auth_url(): void
    {
        $provider = $this->provider();

        $redirectResponse = $provider->stateless()->redirect();
        $targetUrl = $redirectResponse->getTargetUrl();

        $this->assertStringStartsWith('https://my.uzairports.com/oauth/authorize', $targetUrl);
        $this->assertStringContainsString('client_id=test-client', $targetUrl);
        $this->assertStringContainsString('redirect_uri='.urlencode('https://app.test/callback'), $targetUrl);
    }

    public function test_custom_host_can_be_configured(): void
    {
        $provider = $this->provider();
        $provider->setHost('https://staging.uzairports.com');

        $this->assertSame('https://staging.uzairports.com', $provider->getHost());
    }

    public function test_the_authorization_code_is_bound_to_a_pkce_verifier(): void
    {
        $response = $this->get(route('login'));

        $location = (string) $response->headers->get('Location');

        $this->assertStringContainsString('code_challenge=', $location);
        $this->assertStringContainsString('code_challenge_method=S256', $location);
        $this->assertNotNull(session('code_verifier'));
    }

    public function test_pkce_can_be_turned_off_for_a_provider_that_rejects_it(): void
    {
        config(['uzairports.pkce' => false]);

        $location = (string) $this->get(route('login'))->headers->get('Location');

        $this->assertStringNotContainsString('code_challenge', $location);
    }

    public function test_configured_scopes_are_requested_as_a_space_separated_list(): void
    {
        config(['uzairports.scopes' => ['profile', 'email']]);

        $location = (string) $this->get(route('login'))->headers->get('Location');

        $this->assertStringContainsString('scope='.urlencode('profile email'), $location);
    }

    public function test_a_profile_response_that_is_not_a_json_object_is_rejected(): void
    {
        $provider = $this->provider([
            'handler' => HandlerStack::create(new MockHandler([
                new Response(200, [], '"maintenance"'),
            ])),
        ]);

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('not a JSON object');

        $provider->userFromToken('access-token');
    }

    public function test_a_driver_resolved_from_the_container_reads_the_configured_host(): void
    {
        config(['uzairports.host' => 'https://staging.uzairports.com/']);

        /** @var UzairportsProvider $provider */
        $provider = Socialite::driver('uzairports');

        $this->assertSame('https://staging.uzairports.com', $provider->getHost());
    }

    /**
     * @param  array<string, mixed>  $guzzle
     */
    private function provider(array $guzzle = []): UzairportsProvider
    {
        return new UzairportsProvider(
            Request::create('/'),
            'test-client',
            'test-secret',
            'https://app.test/callback',
            $guzzle,
        );
    }
}
