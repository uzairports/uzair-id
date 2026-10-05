<?php

namespace Uzairports\Uzairid\Tests;

use Illuminate\Foundation\Application;
use Illuminate\Routing\Router;
use Illuminate\Testing\TestResponse;
use Laravel\Socialite\Facades\Socialite;
use Mockery;
use Mockery\MockInterface;
use PHPUnit\Framework\Attributes\DataProvider;
use RuntimeException;
use stdClass;
use Symfony\Component\HttpFoundation\Response;
use Uzairports\Uzairid\Models\OauthToken;
use Uzairports\Uzairid\Socialite\UzairportsProvider;
use Uzairports\Uzairid\Uzair;

class UzairBackchannelLogoutTest extends TestCase
{
    use SignsIdentityTokens;

    private const string ISSUER = 'https://my.uzairports.com';

    private MockInterface $provider;

    protected function setUp(): void
    {
        parent::setUp();

        $this->provider = Mockery::mock(UzairportsProvider::class);
        $this->provider->shouldReceive('issuer')->andReturn(self::ISSUER);
        $this->provider->shouldReceive('getClientId')->andReturn('test-client-id');
        $this->provider->shouldReceive('jwksUrl')->andReturn(self::ISSUER.'/oauth/jwks');
        $this->provider->shouldReceive('jwks')->andReturn($this->keySet())->byDefault();

        Socialite::shouldReceive('driver')->with('uzairports')->andReturn($this->provider);
    }

    protected function tearDown(): void
    {
        Mockery::close();

        parent::tearDown();
    }

    /**
     * @param  Application  $app
     */
    protected function defineEnvironment($app): void
    {
        parent::defineEnvironment($app);

        $app['config']->set('uzairports.oidc.enabled', true);
    }

    protected function defineRoutes($router): void
    {
        parent::defineRoutes($router);

        /** @var Router $router */
        $router->prefix('api')->group(fn () => Uzair::backchannelLogoutRoutes());
    }

    public function test_a_logout_naming_a_session_ends_the_logins_filed_under_it_and_hands_their_grants_back(): void
    {
        $user = TestUser::query()->create(['uzair_id' => '9001']);
        $ended = $this->login($user, 'idp-session', 'ended-access');
        $kept = $this->login($user, 'another-idp-session', 'kept-access');

        $this->provider->shouldReceive('logoutAsync')->with('ended-access')->once()->andReturn($this->revoked());
        $this->provider->shouldReceive('revokeRefreshTokenAsync')->with('refresh')->once()->andReturn($this->revoked());

        $this->logout(['sid' => 'idp-session', 'sub' => '9001'])
            ->assertOk()
            ->assertHeader('Cache-Control', 'no-store, private');

        $this->assertModelMissing($ended);
        $this->assertModelExists($kept);
    }

    public function test_a_logout_naming_only_the_account_ends_every_login_it_holds(): void
    {
        $this->acceptRevocations();

        $user = TestUser::query()->create(['uzair_id' => '9002']);
        $someoneElse = TestUser::query()->create(['uzair_id' => '9003']);
        $this->login($user, 'first');
        $this->login($user, 'second');
        $survivor = $this->login($someoneElse, 'third');

        $this->logout(['sub' => '9002'])->assertOk();

        $this->assertSame(0, $user->uzairTokens()->count());
        $this->assertModelExists($survivor);
    }

    public function test_a_session_named_with_another_account_ends_nothing(): void
    {
        $user = TestUser::query()->create(['uzair_id' => '9004']);
        $login = $this->login($user, 'idp-session');

        $this->logout(['sid' => 'idp-session', 'sub' => 'somebody-else'])->assertOk();

        $this->assertModelExists($login);
    }

    public function test_grants_are_not_handed_back_when_revocation_is_declined(): void
    {
        config(['uzairports.revoke_on_backchannel_logout' => false]);
        $this->provider->shouldNotReceive('logoutAsync');

        $user = TestUser::query()->create(['uzair_id' => '9005']);
        $login = $this->login($user, 'idp-session');

        $this->logout(['sid' => 'idp-session'])->assertOk();

        $this->assertModelMissing($login);
    }

    /**
     * @param  array<string, mixed>  $claims
     */
    #[DataProvider('untrustworthyTokens')]
    public function test_a_token_that_cannot_be_trusted_is_refused_and_ends_nothing(array $claims, string $key): void
    {
        $user = TestUser::query()->create(['uzair_id' => '9006']);
        $login = $this->login($user, 'idp-session');

        $this->logout($claims, $key)
            ->assertStatus(400)
            ->assertExactJson(['error' => 'invalid_request']);

        $this->assertModelExists($login);
    }

    /**
     * @return array<string, array{0: array<string, mixed>, 1: string}>
     */
    public static function untrustworthyTokens(): array
    {
        return [
            'signed by another key' => [['sid' => 'idp-session'], 'impostor'],
            'issued by another provider' => [['sid' => 'idp-session', 'iss' => 'https://evil.test'], 'identity-provider'],
            'issued to another client' => [['sid' => 'idp-session', 'aud' => 'another-client'], 'identity-provider'],
            'an ID token, not a logout token' => [['sid' => 'idp-session', 'events' => null], 'identity-provider'],
            'carrying a nonce' => [['sid' => 'idp-session', 'nonce' => 'n'], 'identity-provider'],
            'naming nobody' => [[], 'identity-provider'],
            'issued too long ago' => [['sid' => 'idp-session', 'iat' => time() - 3600], 'identity-provider'],
        ];
    }

    /**
     * Ending many sessions at once is many calls from one address; a 429 the
     * provider may never retry would leave those logins standing.
     */
    public function test_the_endpoint_is_not_held_to_the_sign_in_budget(): void
    {
        config(['uzairports.routes.throttle' => '1,1', 'uzairports.routes.ip_throttle' => '1,1']);

        $this->post(route('uzair.backchannelLogout'))->assertStatus(400);
        $this->post(route('uzair.backchannelLogout'))->assertStatus(400);
    }

    public function test_a_request_without_a_logout_token_is_refused(): void
    {
        $this->post(route('uzair.backchannelLogout'))->assertStatus(400);
    }

    /**
     * A copy replayed later must not end the logins made since.
     */
    public function test_a_replayed_logout_token_ends_nothing_more(): void
    {
        $this->acceptRevocations();

        $user = TestUser::query()->create(['uzair_id' => '9007']);
        $this->login($user, 'before');

        $token = $this->logoutToken(['sub' => '9007']);

        $this->post(route('uzair.backchannelLogout'), ['logout_token' => $token])->assertOk();

        $signedInSince = $this->login($user, 'since');

        $this->post(route('uzair.backchannelLogout'), ['logout_token' => $token])->assertOk();

        $this->assertModelExists($signedInSince);
    }

    /**
     * Keys that cannot be fetched are this side's failure: the provider is
     * told to try again rather than that its token was bad.
     */
    public function test_keys_that_cannot_be_fetched_are_not_answered_as_a_bad_token(): void
    {
        $this->withoutExceptionHandling();
        $this->provider->shouldReceive('jwks')->andThrow(new RuntimeException('UzAirports SSO did not answer with its signing keys.'));

        $this->expectException(RuntimeException::class);

        $this->logout(['sid' => 'idp-session']);
    }

    /**
     * @param  array<string, mixed>  $claims
     * @return TestResponse<Response>
     */
    private function logout(array $claims, string $key = 'identity-provider'): TestResponse
    {
        return $this->post(route('uzair.backchannelLogout'), ['logout_token' => $this->logoutToken($claims, $key)]);
    }

    /**
     * @param  array<string, mixed>  $claims
     */
    private function logoutToken(array $claims, string $key = 'identity-provider'): string
    {
        return $this->signed(array_filter([
            'iss' => self::ISSUER,
            'aud' => 'test-client-id',
            'iat' => time(),
            'jti' => bin2hex(random_bytes(8)),
            'events' => ['http://schemas.openid.net/event/backchannel-logout' => new stdClass],
            ...$claims,
        ], fn (mixed $value): bool => $value !== null), $key);
    }

    private function acceptRevocations(): void
    {
        $this->provider->shouldReceive('logoutAsync')->andReturnUsing(fn () => $this->revoked());
        $this->provider->shouldReceive('revokeRefreshTokenAsync')->andReturnUsing(fn () => $this->revoked());
    }

    private function login(TestUser $user, string $sid, string $accessToken = 'access'): OauthToken
    {
        $login = (new OauthToken)->forceFill([
            'user_id' => $user->getKey(),
            'session_id' => "browser-{$sid}",
            'sid' => $sid,
            'access_token' => $accessToken,
            'refresh_token' => 'refresh',
            'expires_at' => now()->addHour(),
        ]);
        $login->save() || throw new RuntimeException('The login was not written.');

        return $login;
    }
}
