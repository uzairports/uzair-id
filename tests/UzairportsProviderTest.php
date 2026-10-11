<?php

namespace Uzairports\Uzairid\Tests;

use GuzzleHttp\Exception\GuzzleException;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use GuzzleHttp\Psr7\Response;
use Illuminate\Http\Request;
use Laravel\Socialite\Facades\Socialite;
use Mockery;
use PHPUnit\Framework\Attributes\DataProvider;
use Psr\Http\Message\RequestInterface;
use RuntimeException;
use TypeError;
use UnexpectedValueException;
use Uzairports\Uzairid\Socialite\UzairportsProvider;

class UzairportsProviderTest extends TestCase
{
    use SignsIdentityTokens;

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

    /**
     * Every call carries a credential and the signing keys come back the same
     * way, so a plain-text host would hand both to whoever sits in between.
     */
    public function test_a_plain_http_host_is_refused_outside_local_and_testing(): void
    {
        app()->detectEnvironment(fn (): string => 'production');
        config(['uzairports.host' => 'http://my.uzairports.com']);

        $this->expectException(RuntimeException::class);

        $this->provider()->getHost();
    }

    public function test_a_plain_http_endpoint_is_refused_outside_local_and_testing(): void
    {
        app()->detectEnvironment(fn (): string => 'production');
        config(['uzairports.oidc.jwks_endpoint' => 'http://keys.test/jwks']);

        $this->expectException(RuntimeException::class);

        $this->provider()->jwksUrl();
    }

    public function test_a_plain_http_host_is_accepted_in_the_local_environment(): void
    {
        app()->detectEnvironment(fn (): string => 'local');
        config(['uzairports.host' => 'http://localhost:8001', 'uzairports.user_endpoint' => '/api/user']);

        $this->assertSame('http://localhost:8001/api/user', $this->provider()->userUrl());
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

    public function test_a_clients_code_is_exchanged_with_its_own_verifier_and_redirect_uri_without_a_session(): void
    {
        $stack = HandlerStack::create(new MockHandler([
            function (RequestInterface $request): Response {
                parse_str((string) $request->getBody(), $fields);

                $this->assertSame('authorization_code', $fields['grant_type']);
                $this->assertSame('test-secret', $fields['client_secret']);
                $this->assertSame('client-code', $fields['code']);
                $this->assertSame('uzapp://auth/callback', $fields['redirect_uri']);
                $this->assertSame('client-verifier', $fields['code_verifier']);

                return new Response(200, [], '{"access_token":"access","refresh_token":"refresh","expires_in":3600}');
            },
            new Response(200, [], '{"id":"42","name":"Pilot"}'),
        ]));
        $request = Request::create('/');
        $request->setLaravelSession(app('session.store'));
        $provider = new UzairportsProvider($request, 'test-client', 'test-secret', 'https://app.test/callback', ['handler' => $stack]);
        $provider->enablePKCE();

        $user = $provider->userFromCode('client-code', 'uzapp://auth/callback', 'client-verifier');

        $this->assertSame('42', $user->getId());
        $this->assertSame('refresh', $user->refreshToken);

        // The instance Socialite keeps for the browser flow is left as it was.
        $this->assertStringContainsString(
            'redirect_uri='.urlencode('https://app.test/callback'),
            $provider->stateless()->redirect()->getTargetUrl(),
        );
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

    /**
     * The code is exchanged before the profile is asked for, so a provider that
     * answers the first call and fails the second has already issued a live
     * access token and a live refresh token — and `user()` throws instead of
     * handing them back, so no caller can give them up on its behalf. Nothing
     * would ever point at them: no row is written, and `model:prune` sweeps
     * rows.
     *
     * This is the likelier of the two ways a callback fails, being a second
     * round trip to the identity provider with a timeout of its own.
     */
    /**
     * These requests do not follow redirects, so a 302 comes back as an
     * ordinary response and Guzzle raises nothing over it. A gateway in front
     * of the identity provider answering one with a body of its own was mapped
     * into a user and signed in.
     */
    public function test_a_profile_answered_by_a_redirect_is_refused(): void
    {
        $provider = $this->provider([
            'handler' => HandlerStack::create(new MockHandler([
                new Response(302, ['Location' => 'https://gateway.test/login'], '{"id":"synthetic-user"}'),
            ])),
        ]);

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('did not answer with a user profile');

        $provider->userFromToken('access-token');
    }

    /**
     * `uzairports.guzzle` is merged into the client, so an application may turn
     * `http_errors` off — and then a refusal arrives as an ordinary response
     * carrying whatever the identity provider put in it. The token exchange
     * beside this has always read the status for itself.
     */
    public function test_a_refused_profile_is_not_read_as_one_when_guzzle_raises_nothing(): void
    {
        $provider = $this->provider([
            'http_errors' => false,
            'handler' => HandlerStack::create(new MockHandler([
                new Response(500, [], '{"id":"whatever-the-error-page-carried"}'),
            ])),
        ]);

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('did not answer with a user profile');

        $provider->userFromToken('access-token');
    }

    public function test_a_profile_request_that_fails_surrenders_the_issued_grants(): void
    {
        $revoker = Mockery::mock(UzairportsProvider::class);
        $revoker->shouldReceive('logoutAsync')->with('issued-access')->once()->andReturn($this->revoked());
        $revoker->shouldReceive('revokeRefreshTokenAsync')->with('issued-refresh')->once()->andReturn($this->revoked());

        Socialite::shouldReceive('driver')->with('uzairports')->andReturn($revoker);

        $provider = $this->provider([
            'handler' => HandlerStack::create(new MockHandler([
                new Response(200, [], '{"access_token":"issued-access","refresh_token":"issued-refresh","expires_in":3600}'),
                new Response(503, [], 'the identity provider is not answering'),
            ])),
        ])->stateless();

        try {
            $provider->user();

            $this->fail('A profile request that failed must not hand back a user.');
        } catch (GuzzleException) {
            $this->addToAssertionCount(1);
        }
    }

    public function test_a_user_mapping_failure_surrenders_grants_and_discards_the_partial_user(): void
    {
        $revoker = Mockery::mock(UzairportsProvider::class);
        $revoker->shouldReceive('logoutAsync')->with('issued-access')->once()->andReturn($this->revoked());
        $revoker->shouldReceive('revokeRefreshTokenAsync')->with('issued-refresh')->once()->andReturn($this->revoked());
        Socialite::shouldReceive('driver')->with('uzairports')->andReturn($revoker);

        $provider = $this->provider([
            'handler' => HandlerStack::create(new MockHandler([
                new Response(200, [], '{"access_token":"issued-access","refresh_token":"issued-refresh","scope":[]}'),
                new Response(200, [], '{"id":"first-user"}'),
                new Response(200, [], '{"access_token":"next-access","scope":"profile"}'),
                new Response(200, [], '{"id":"next-user"}'),
            ])),
        ])->stateless();

        try {
            $provider->user();
            $this->fail('An invalid scope must not produce an authenticated user.');
        } catch (TypeError) {
            $this->assertSame('next-user', $provider->user()->getId());
            $this->assertSame('next-access', $provider->user()->token);
        }
    }

    public function test_sub_claim_is_used_as_fallback_for_user_id(): void
    {
        $provider = $this->provider([
            'handler' => HandlerStack::create(new MockHandler([
                new Response(200, [], '{"sub":"subject-uuid-123","name":"Test User","email":"user@example.com"}'),
            ])),
        ]);

        $user = $provider->userFromToken('access-token');

        $this->assertSame('subject-uuid-123', $user->getId());
        $this->assertSame('Test User', $user->getName());
        $this->assertSame('user@example.com', $user->getEmail());
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

    public function test_an_authorization_response_from_another_issuer_is_refused_before_the_code_is_spent(): void
    {
        foreach (['https://evil.test', null] as $issuer) {
            $history = [];
            $stack = HandlerStack::create(new MockHandler([]));
            $stack->push(Middleware::history($history));

            try {
                $this->callbackProvider(['handler' => $stack], $issuer)->user();

                $this->fail('A response the configured provider did not issue must be refused.');
            } catch (RuntimeException $exception) {
                $this->assertSame('The authorization response was not issued by the configured UzAirports ID.', $exception->getMessage());
            }

            $this->assertSame([], $history);
        }
    }

    public function test_an_authorization_response_from_the_issuer_is_completed(): void
    {
        $provider = $this->callbackProvider(['handler' => HandlerStack::create(new MockHandler([
            new Response(200, [], '{"access_token":"access","expires_in":3600}'),
            new Response(200, [], '{"id":"42"}'),
        ]))], 'https://my.uzairports.com');

        $this->assertSame('42', $provider->user()->getId());
    }

    /**
     * OpenID Connect compares issuers as strings, so an issuer that ends in a
     * slash must be matched with it rather than trimmed into a mismatch.
     */
    public function test_an_issuer_ending_in_a_slash_is_matched_as_configured(): void
    {
        config(['uzairports.issuer' => 'https://my.uzairports.com/']);

        $provider = $this->callbackProvider(['handler' => HandlerStack::create(new MockHandler([
            new Response(200, [], '{"access_token":"access","expires_in":3600}'),
            new Response(200, [], '{"id":"42"}'),
        ]))], 'https://my.uzairports.com/');

        $this->assertSame('42', $provider->user()->getId());
    }

    public function test_a_response_without_iss_is_completed_where_it_is_not_required(): void
    {
        config(['uzairports.require_iss' => false]);

        $provider = $this->callbackProvider(['handler' => HandlerStack::create(new MockHandler([
            new Response(200, [], '{"access_token":"access","expires_in":3600}'),
            new Response(200, [], '{"id":"42"}'),
        ]))], null);

        $this->assertSame('42', $provider->user()->getId());
    }

    public function test_the_id_token_is_verified_and_its_session_kept(): void
    {
        config(['uzairports.oidc.enabled' => true]);

        $user = $this->providerIssuing($this->signed($this->idTokenClaims()))->stateless()->user();

        $this->assertSame('idp-session', $user->attributes['sid']);
        $this->assertIsString($user->attributes['id_token']);
    }

    /**
     * @param  array<string, mixed>  $claims
     */
    #[DataProvider('untrustworthyIdTokens')]
    public function test_an_id_token_that_cannot_be_trusted_fails_the_sign_in_and_surrenders_the_grants(array $claims, string $key): void
    {
        config(['uzairports.oidc.enabled' => true]);

        $revoker = Mockery::mock(UzairportsProvider::class);
        $revoker->shouldReceive('logoutAsync')->with('issued-access')->once()->andReturn($this->revoked());
        $revoker->shouldReceive('revokeRefreshTokenAsync')->with('issued-refresh')->once()->andReturn($this->revoked());
        Socialite::shouldReceive('driver')->with('uzairports')->andReturn($revoker);

        $provider = $this->providerIssuing($this->signed([...$this->idTokenClaims(), ...$claims], $key))->stateless();

        try {
            $provider->user();

            $this->fail('An ID token that cannot be trusted must not sign anybody in.');
        } catch (UnexpectedValueException|RuntimeException) {
            $this->addToAssertionCount(1);
        }
    }

    /**
     * @return array<string, array{0: array<string, mixed>, 1: string}>
     */
    public static function untrustworthyIdTokens(): array
    {
        return [
            'signed by another key' => [[], 'impostor'],
            'naming another subject' => [['sub' => 'somebody-else'], 'identity-provider'],
            'issued to another client' => [['aud' => 'another-client'], 'identity-provider'],
            'issued by another provider' => [['iss' => 'https://evil.test'], 'identity-provider'],
            'expired' => [['exp' => time() - 3600], 'identity-provider'],
        ];
    }

    public function test_the_session_at_the_identity_provider_is_ended_through_its_end_session_endpoint(): void
    {
        $this->assertNull($this->provider()->endSessionUrl('https://app.test/'));

        config(['uzairports.end_session_endpoint' => '/oauth/logout']);

        $this->assertSame(
            'https://my.uzairports.com/oauth/logout?client_id=test-client&post_logout_redirect_uri=https%3A%2F%2Fapp.test%2F&id_token_hint=the-id-token',
            $this->provider()->endSessionUrl('https://app.test/', 'the-id-token'),
        );
    }

    public function test_an_id_token_algorithm_not_allowed_is_refused(): void
    {
        config(['uzairports.oidc.enabled' => true, 'uzairports.oidc.algorithms' => ['ES256']]);

        $revoker = Mockery::mock(UzairportsProvider::class);
        $revoker->shouldReceive('logoutAsync')->with('issued-access')->once()->andReturn($this->revoked());
        $revoker->shouldReceive('revokeRefreshTokenAsync')->with('issued-refresh')->once()->andReturn($this->revoked());
        Socialite::shouldReceive('driver')->with('uzairports')->andReturn($revoker);

        $provider = $this->providerIssuing($this->signed($this->idTokenClaims()))->stateless();

        $this->expectException(UnexpectedValueException::class);
        $provider->user();
    }

    public function test_redirect_includes_nonce_when_oidc_is_enabled(): void
    {
        config(['uzairports.oidc.enabled' => true]);

        $request = Request::create('https://app.test/auth/redirect');
        $session = app('session.store');
        $request->setLaravelSession($session);

        $provider = new UzairportsProvider($request, 'test-client', 'test-secret', 'https://app.test/callback', []);

        $response = $provider->redirect();
        $url = $response->getTargetUrl();

        $this->assertTrue($session->has('uzairid.nonce'));
        $nonce = $session->get('uzairid.nonce');
        $this->assertIsString($nonce);
        $this->assertNotEmpty($nonce);
        $this->assertStringContainsString('nonce='.$nonce, $url);
    }

    public function test_id_token_with_mismatched_nonce_is_rejected(): void
    {
        config(['uzairports.oidc.enabled' => true]);

        $request = Request::create('https://app.test/auth/callback?code=the-code&state=the-state&iss=https://my.uzairports.com');
        $session = app('session.store');
        $session->put('state', 'the-state');
        $session->put('uzairid.nonce', 'expected-nonce-value');
        $request->setLaravelSession($session);

        $revoker = Mockery::mock(UzairportsProvider::class);
        $revoker->shouldReceive('logoutAsync')->with('issued-access')->once()->andReturn($this->revoked());
        $revoker->shouldReceive('revokeRefreshTokenAsync')->with('issued-refresh')->once()->andReturn($this->revoked());
        Socialite::shouldReceive('driver')->with('uzairports')->andReturn($revoker);

        $provider = $this->providerIssuing($this->signed([...$this->idTokenClaims(), 'nonce' => 'wrong-nonce']));
        $provider->setRequest($request);

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('The UzAirports ID token nonce is missing or does not match the session nonce.');

        $provider->user();
    }

    public function test_id_token_without_session_nonce_is_rejected(): void
    {
        config(['uzairports.oidc.enabled' => true]);

        $request = Request::create('https://app.test/auth/callback?code=the-code&state=the-state&iss=https://my.uzairports.com');
        $session = app('session.store');
        $session->put('state', 'the-state');
        // No uzairid.nonce in session
        $request->setLaravelSession($session);

        $revoker = Mockery::mock(UzairportsProvider::class);
        $revoker->shouldReceive('logoutAsync')->with('issued-access')->once()->andReturn($this->revoked());
        $revoker->shouldReceive('revokeRefreshTokenAsync')->with('issued-refresh')->once()->andReturn($this->revoked());
        Socialite::shouldReceive('driver')->with('uzairports')->andReturn($revoker);

        $provider = $this->providerIssuing($this->signed([...$this->idTokenClaims(), 'nonce' => 'any-nonce']));
        $provider->setRequest($request);

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('The UzAirports ID token nonce is missing or does not match the session nonce.');

        $provider->user();
    }

    public function test_multiple_concurrent_login_nonces_are_supported(): void
    {
        config(['uzairports.oidc.enabled' => true]);

        $session = app('session.store');

        $request1 = Request::create('https://app.test/auth/redirect');
        $request1->setLaravelSession($session);
        $provider1 = new UzairportsProvider($request1, 'test-client', 'test-secret', 'https://app.test/callback', []);
        $response1 = $provider1->redirect();
        preg_match('/state=([^&]+)/', $response1->getTargetUrl(), $stateMatches1);
        $state1 = $stateMatches1[1] ?? '';
        preg_match('/nonce=([^&]+)/', $response1->getTargetUrl(), $matches1);
        $nonce1 = $matches1[1] ?? '';

        $request2 = Request::create('https://app.test/auth/redirect');
        $request2->setLaravelSession($session);
        $provider2 = new UzairportsProvider($request2, 'test-client', 'test-secret', 'https://app.test/callback', []);
        $response2 = $provider2->redirect();
        preg_match('/state=([^&]+)/', $response2->getTargetUrl(), $stateMatches2);
        $state2 = $stateMatches2[1] ?? '';
        preg_match('/nonce=([^&]+)/', $response2->getTargetUrl(), $matches2);
        $nonce2 = $matches2[1] ?? '';

        $this->assertNotEmpty($nonce1);
        $this->assertNotEmpty($nonce2);
        $this->assertNotSame($nonce1, $nonce2);

        $nonces = $session->get('uzairid.nonces');
        $this->assertIsArray($nonces);
        $this->assertContains($nonce1, $nonces);
        $this->assertContains($nonce2, $nonces);

        $callbackRequest1 = Request::create('https://app.test/auth/callback?code=the-code-1&state='.$state1.'&iss=https://my.uzairports.com');
        $callbackRequest1->setLaravelSession($session);
        $providerForCallback1 = $this->providerIssuing($this->signed([...$this->idTokenClaims(), 'nonce' => $nonce1]));
        $providerForCallback1->setRequest($callbackRequest1);

        $user1 = $providerForCallback1->user();
        $this->assertSame('42', $user1->getId());

        $noncesAfter1 = (array) $session->get('uzairid.nonces');
        $this->assertNotContains($nonce1, $noncesAfter1);
        $this->assertContains($nonce2, $noncesAfter1);

        $replayRequest = Request::create('https://app.test/auth/callback?code=the-code-2&state='.$state2.'&iss=https://my.uzairports.com');
        $replayRequest->setLaravelSession($session);
        $revoker = Mockery::mock(UzairportsProvider::class);
        $revoker->shouldReceive('logoutAsync')->once()->andReturn($this->revoked());
        $revoker->shouldReceive('revokeRefreshTokenAsync')->once()->andReturn($this->revoked());
        Socialite::shouldReceive('driver')->with('uzairports')->andReturn($revoker);

        $replayProvider = $this->providerIssuing($this->signed([...$this->idTokenClaims(), 'nonce' => $nonce1]));
        $replayProvider->setRequest($replayRequest);

        try {
            $replayProvider->user();
            $this->fail('Replaying consumed nonce should fail');
        } catch (RuntimeException $e) {
            $this->assertStringContainsString('session nonce', $e->getMessage());
        }
    }

    public function test_jwks_with_unrelated_algorithm_key_still_allows_supported_key(): void
    {
        config(['uzairports.oidc.enabled' => true, 'uzairports.oidc.algorithms' => ['RS256']]);

        $jwks = $this->keySet();
        $jwks['keys'][] = [
            'kty' => 'EC',
            'alg' => 'ES256',
            'crv' => 'P-256',
            'x' => 'f83OJ3D2xFmTtx9ErC2PEUtqEZ_ZMVAEBmmT3BmvpHg',
            'y' => 'x_daQauBhQ0tZxFlGQM25odEL9VEqOCTWhGC24A9xCY',
            'use' => 'sig',
            'kid' => 'key-ec',
        ];

        $provider = $this->providerIssuing(
            $this->signed($this->idTokenClaims()),
            keySet: $jwks,
        )->stateless();

        $user = $provider->user();
        $this->assertSame('42', $user->getId());
    }

    /**
     * A provider answering a callback whose state matches.
     *
     * @param  array<string, mixed>  $guzzle
     */
    private function callbackProvider(array $guzzle, ?string $issuer): UzairportsProvider
    {
        $request = Request::create('/callback', 'GET', array_filter(['code' => 'code', 'state' => 'state', 'iss' => $issuer]));
        $request->setLaravelSession(app('session.store'));
        $request->session()->put('state', 'state');

        return new UzairportsProvider($request, 'test-client', 'test-secret', 'https://app.test/callback', $guzzle);
    }

    /**
     * A provider whose exchange issues the given ID token beside the grants.
     *
     * @param  array<string, mixed>|null  $keySet
     */
    private function providerIssuing(string $idToken, ?array $keySet = null): UzairportsProvider
    {
        return $this->provider(['handler' => HandlerStack::create(new MockHandler([
            new Response(200, [], (string) json_encode([
                'access_token' => 'issued-access',
                'refresh_token' => 'issued-refresh',
                'expires_in' => 3600,
                'id_token' => $idToken,
            ])),
            new Response(200, [], '{"id":"42"}'),
            new Response(200, [], (string) json_encode($keySet ?? $this->keySet())),
        ]))]);
    }

    /**
     * @return array<string, mixed>
     */
    private function idTokenClaims(): array
    {
        return [
            'iss' => 'https://my.uzairports.com',
            'aud' => 'test-client',
            'sub' => '42',
            'sid' => 'idp-session',
            'iat' => time(),
            'exp' => time() + 300,
        ];
    }

    /**
     * A handler stack that answers with 200 and writes down what it was asked.
     */
    private function recordingStack(RecordedRequest $recorded): callable
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
