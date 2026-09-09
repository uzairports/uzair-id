<?php

namespace Uzairports\Uzairid\Tests;

use GuzzleHttp\Exception\GuzzleException;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use GuzzleHttp\Psr7\Response;
use Illuminate\Http\Request;
use Laravel\Socialite\Facades\Socialite;
use Psr\Http\Message\RequestInterface;
use RuntimeException;
use Uzairports\Uzairid\Socialite\UzairportsProvider;

class UzairportsProviderTest extends TestCase
{
    public function test_code_exchange_never_forwards_credentials_to_a_redirect(): void
    {
        foreach ([301, 302, 303, 307, 308] as $status) {
            $history = [];
            $stack = HandlerStack::create(new MockHandler([
                new Response($status, ['Location' => 'https://other.test/token'], '{"access_token":"redirect-body"}'),
                new Response(200, [], '{"access_token":"unexpected"}'),
            ]));
            $stack->push(Middleware::history($history));
            $provider = $this->provider(['handler' => $stack, 'allow_redirects' => true]);

            try {
                $provider->getAccessTokenResponse('authorization-code');
                $this->fail('A token endpoint redirect must fail the exchange.');
            } catch (RuntimeException $exception) {
                $this->assertSame('UzAirports SSO returned an invalid token response.', $exception->getMessage());
            }

            $this->assertIsArray($history);
            $this->assertCount(1, $history);
            $this->assertSame('my.uzairports.com', $history[0]['request']->getUri()->getHost());
        }
    }

    public function test_code_exchange_preserves_pkce_and_client_credentials(): void
    {
        $request = Request::create('/callback');
        $request->setLaravelSession(app('session.store'));
        $request->session()->put('code_verifier', 'test-verifier');

        $stack = HandlerStack::create(new MockHandler([
            function (RequestInterface $request, array $options): Response {
                parse_str((string) $request->getBody(), $fields);

                $this->assertSame('POST', $request->getMethod());
                $this->assertSame('test-client', $fields['client_id']);
                $this->assertSame('test-secret', $fields['client_secret']);
                $this->assertSame('authorization-code', $fields['code']);
                $this->assertSame('test-verifier', $fields['code_verifier']);
                $this->assertSame('authorization_code', $fields['grant_type']);
                $this->assertSame(10, $options['timeout']);

                return new Response(200, [], '{"access_token":"access","refresh_token":"refresh","expires_in":3600}');
            },
        ]));
        $provider = new UzairportsProvider($request, 'test-client', 'test-secret', 'https://app.test/callback', ['handler' => $stack]);
        $provider->enablePKCE();

        $this->assertSame([
            'access_token' => 'access',
            'refresh_token' => 'refresh',
            'expires_in' => 3600,
        ], $provider->getAccessTokenResponse('authorization-code'));
    }

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
     * A provider that offers no revocation endpoint must not be guessed at: a
     * logout would then pay a failed request every time.
     *
     * @throws GuzzleException
     */
    public function test_no_refresh_token_is_revoked_without_a_configured_endpoint(): void
    {
        config(['uzairports.revoke_endpoint' => null]);

        $this->assertNull($this->provider()->revokeRefreshToken('refresh-token-value'));
    }

    /**
     * @throws GuzzleException
     */
    public function test_a_refresh_token_is_surrendered_as_an_rfc_7009_revocation(): void
    {
        config(['uzairports.revoke_endpoint' => '/oauth/revoke']);

        $recorded = new RecordedRequest;

        $response = $this->provider(['handler' => $this->recordingStack($recorded)])
            ->revokeRefreshToken('refresh-token-value');

        $this->assertNotNull($response);
        $this->assertSame('POST', $recorded->method);
        $this->assertSame('https://my.uzairports.com/oauth/revoke', $recorded->uri);

        parse_str((string) $recorded->body, $body);

        $this->assertSame([
            'token' => 'refresh-token-value',
            'token_type_hint' => 'refresh_token',
            'client_id' => 'test-client',
            'client_secret' => 'test-secret',
        ], $body);
    }

    /**
     * @throws GuzzleException
     */
    public function test_a_revocation_endpoint_may_be_a_full_url(): void
    {
        config(['uzairports.revoke_endpoint' => 'https://auth.uzairports.com/revoke']);

        $recorded = new RecordedRequest;

        $this->provider(['handler' => $this->recordingStack($recorded)])
            ->revokeRefreshToken('refresh-token-value');

        $this->assertSame('https://auth.uzairports.com/revoke', $recorded->uri);
    }

    public function test_refresh_uses_the_effective_timeout_without_following_redirects(): void
    {
        config(['uzairports.timeout' => 10, 'uzairports.guzzle.timeout' => 30.5]);

        $provider = $this->provider(['handler' => HandlerStack::create(new MockHandler([
            function (RequestInterface $request, array $options): Response {
                $this->assertSame(31, $options['timeout']);
                $this->assertSame(5, $options['connect_timeout']);
                $this->assertFalse($options['allow_redirects']);

                return new Response(200, [], '{"access_token":"new-access","expires_in":3600}');
            },
        ]))]);

        $this->assertSame('new-access', $provider->refreshToken('old-refresh')->token);
    }

    public function test_invalid_timeouts_cannot_make_refresh_requests_wait_forever(): void
    {
        foreach ([0, -1, 'invalid'] as $timeout) {
            config(['uzairports.timeout' => $timeout, 'uzairports.connect_timeout' => $timeout]);

            $provider = $this->provider(['handler' => HandlerStack::create(new MockHandler([
                function (RequestInterface $request, array $options): Response {
                    $this->assertSame(10, $options['timeout']);
                    $this->assertSame(5, $options['connect_timeout']);

                    return new Response(200, [], '{"access_token":"new-access","expires_in":3600}');
                },
            ]))]);

            $this->assertSame('new-access', $provider->refreshToken('old-refresh')->token);
        }
    }

    public function test_refresh_accepts_an_omitted_refresh_token_and_expiry(): void
    {
        $provider = $this->provider(['handler' => HandlerStack::create(new MockHandler([
            new Response(200, [], '{"access_token":"new-access"}'),
        ]))]);

        $token = $provider->refreshToken('old-refresh');

        $this->assertSame('new-access', $token->token);
        $this->assertSame('', $token->refreshToken);
        $this->assertSame(0, $token->expiresIn);
    }

    public function test_a_logout_redirect_does_not_count_as_a_successful_revocation(): void
    {
        $provider = $this->provider(['handler' => HandlerStack::create(new MockHandler([
            new Response(302, ['Location' => 'https://sso.test/login']),
        ]))]);

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('did not confirm token revocation');

        $provider->logout('access-token');
    }

    public function test_a_refresh_revocation_redirect_does_not_count_as_success(): void
    {
        config(['uzairports.revoke_endpoint' => '/oauth/revoke']);
        $provider = $this->provider(['handler' => HandlerStack::create(new MockHandler([
            new Response(302, ['Location' => 'https://sso.test/login']),
        ]))]);

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('did not confirm token revocation');

        $provider->revokeRefreshToken('refresh-token');
    }

    /**
     * A handler stack that answers with 200 and writes down what it was asked.
     */
    private function recordingStack(RecordedRequest $recorded): HandlerStack
    {
        $stack = HandlerStack::create(new MockHandler([new Response(200)]));

        $stack->push(fn (callable $handler): callable => function (RequestInterface $request, array $options) use ($handler, $recorded) {
            $recorded->method = $request->getMethod();
            $recorded->uri = (string) $request->getUri();
            $recorded->body = (string) $request->getBody();

            return $handler($request, $options);
        });

        return $stack;
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

/**
 * What a recording handler stack was asked to send.
 */
class RecordedRequest
{
    public ?string $method = null;

    public ?string $uri = null;

    public ?string $body = null;
}
