<?php

namespace Uzairports\Uzairid\Tests;

use Carbon\CarbonInterface;
use GuzzleHttp\Exception\BadResponseException;
use GuzzleHttp\Exception\ConnectException;
use GuzzleHttp\Psr7\Request as PsrRequest;
use GuzzleHttp\Psr7\Response as PsrResponse;
use Illuminate\Auth\AuthenticationException;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Foundation\Application;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Http\Request;
use Illuminate\Routing\Router;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Schema;
use Illuminate\Testing\TestResponse;
use Laravel\Sanctum\HasApiTokens;
use Laravel\Sanctum\PersonalAccessToken;
use Laravel\Sanctum\SanctumServiceProvider;
use Laravel\Socialite\Facades\Socialite;
use Laravel\Socialite\Two\User as SocialiteUser;
use Mockery;
use Mockery\MockInterface;
use PHPUnit\Framework\Attributes\DataProvider;
use RuntimeException;
use Symfony\Component\HttpFoundation\Response;
use Uzairports\Uzairid\Actions\EndSessions;
use Uzairports\Uzairid\Actions\RefreshAccessToken;
use Uzairports\Uzairid\Concerns\HasUzairToken;
use Uzairports\Uzairid\Events\UzairAuthenticated;
use Uzairports\Uzairid\Models\OauthToken;
use Uzairports\Uzairid\Socialite\UzairportsProvider;
use Uzairports\Uzairid\Uzair;

class UzairApiAuthControllerTest extends TestCase
{
    private const string REDIRECT_URI = 'uzapp://auth/callback';

    private const string VERIFIER = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';

    protected function tearDown(): void
    {
        Mockery::close();

        parent::tearDown();
    }

    /**
     * @param  Application  $app
     * @return array<int, class-string>
     */
    protected function getPackageProviders($app): array
    {
        return [...parent::getPackageProviders($app), SanctumServiceProvider::class];
    }

    /**
     * @param  Application  $app
     */
    protected function defineEnvironment($app): void
    {
        parent::defineEnvironment($app);

        $app['config']->set('auth.providers.users.model', SanctumUser::class);
        $app['config']->set('uzairports.api.redirect_uris', [self::REDIRECT_URI]);
    }

    protected function defineRoutes($router): void
    {
        parent::defineRoutes($router);

        /** @var Router $router */
        $router->prefix('api')->group(function () use ($router): void {
            Uzair::apiRoutes();

            $router->get('me', fn (Request $request): array => [
                'login' => $request->user() instanceof SanctumUser ? $request->user()->currentToken()?->id : null,
            ])->middleware(['auth:sanctum', 'uzair.token:sanctum']);
        });
    }

    public function test_a_code_is_traded_for_a_sanctum_token_the_login_is_filed_under(): void
    {
        Event::fake([UzairAuthenticated::class]);

        $provider = $this->fakeExchange(['id' => '7001', 'token' => 'sso-access', 'refreshToken' => 'sso-refresh']);

        $response = $this->postJson(route('uzair.api.token'), $this->exchange());

        $response->assertOk()->assertJsonPath('token_type', 'Bearer');

        $user = SanctumUser::query()->where('uzair_id', '7001')->firstOrFail();
        $accessToken = PersonalAccessToken::findToken($this->issuedToken($response));
        $login = $user->uzairTokens()->sole();

        $this->assertNotNull($accessToken);
        $this->assertSame('Pixel 9', $accessToken->getAttribute('name'));
        $this->assertSame($accessToken->getKey(), (int) $login->personal_access_token_id);
        $this->assertNull($login->session_id);
        $this->assertSame('sso-access', $login->access_token);
        $this->assertSame('sso-refresh', $login->refresh_token);

        $provider->shouldHaveReceived('userFromCode')->with('code-from-the-app', self::REDIRECT_URI, self::VERIFIER);
        Event::assertDispatched(UzairAuthenticated::class, fn (UzairAuthenticated $event): bool => $event->token?->is($login) === true);
    }

    public function test_the_issued_token_carries_the_configured_abilities_and_lifetime(): void
    {
        $this->freezeSecond();
        config(['uzairports.api.token_abilities' => ['flights:read'], 'uzairports.api.token_expiration' => 60]);

        $this->fakeExchange(['id' => '7012']);

        $response = $this->postJson(route('uzair.api.token'), $this->exchange())
            ->assertOk()
            ->assertJsonPath('expires_at', now()->addHour()->toIso8601String());

        $accessToken = PersonalAccessToken::findToken($this->issuedToken($response));

        $this->assertNotNull($accessToken);
        $this->assertSame(['flights:read'], $accessToken->getAttribute('abilities'));
        $expiresAt = $accessToken->getAttribute('expires_at');

        $this->assertInstanceOf(CarbonInterface::class, $expiresAt);
        $this->assertSame(now()->addHour()->getTimestamp(), $expiresAt->getTimestamp());
    }

    public function test_the_client_is_told_when_sanctum_retires_a_token_issued_without_its_own_lifetime(): void
    {
        $this->freezeSecond();

        $this->fakeExchange(['id' => '7013']);
        $this->postJson(route('uzair.api.token'), $this->exchange())->assertOk()->assertJsonPath('expires_at', null);

        config(['sanctum.expiration' => 30]);

        $this->fakeExchange(['id' => '7014']);
        $this->postJson(route('uzair.api.token'), $this->exchange())
            ->assertOk()
            ->assertJsonPath('expires_at', now()->addMinutes(30)->toIso8601String());
    }

    #[DataProvider('competingExpirations')]
    public function test_the_issued_token_reports_the_earlier_of_its_own_and_sanctums_expiration(int $tokenMinutes, int $sanctumMinutes): void
    {
        $this->freezeSecond();
        config(['uzairports.api.token_expiration' => $tokenMinutes, 'sanctum.expiration' => $sanctumMinutes]);
        $this->fakeExchange(['id' => '7030']);

        $response = $this->postJson(route('uzair.api.token'), $this->exchange());

        $response->assertOk()->assertJsonPath('expires_at', now()->addMinutes(30)->toIso8601String());
        $this->assertNotNull(PersonalAccessToken::findToken($this->issuedToken($response)));
        $this->assertSame(1, OauthToken::query()->count());
    }

    /**
     * @return array<string, array{int, int}>
     */
    public static function competingExpirations(): array
    {
        return [
            'Sanctum expires first' => [60, 30],
            'the token expires first' => [30, 60],
        ];
    }

    /**
     * A mobile client is public: the server redeems its code with the client
     * secret, so the verifier is all that ties the code to the app that asked
     * for it. Turning PKCE off for the browser must not turn it off here.
     */
    public function test_a_verifier_is_demanded_of_a_client_even_where_browser_pkce_is_off(): void
    {
        config(['uzairports.pkce' => false]);

        Socialite::shouldReceive('driver')->never();

        $this->postJson(route('uzair.api.token'), $this->exchange(['code_verifier' => null]))
            ->assertUnprocessable()
            ->assertJsonValidationErrors('code_verifier');
    }

    public function test_single_session_ends_the_other_logins_but_spares_the_one_just_issued(): void
    {
        config(['uzairports.single_session' => true]);

        $user = SanctumUser::query()->create(['uzair_id' => '7008']);
        [, $earlierPhone] = $this->phoneLogin($user, 'earlier', 'earlier-access');

        $provider = $this->fakeExchange(['id' => '7008', 'token' => 'sso-access', 'refreshToken' => 'sso-refresh']);
        $provider->shouldReceive('logoutAsync')->with('earlier-access')->once()->andReturn($this->revoked());

        $token = $this->issuedToken($this->postJson(route('uzair.api.token'), $this->exchange())->assertOk());

        $this->assertModelMissing($earlierPhone);
        $this->assertSame('sso-access', $user->uzairTokens()->sole()->access_token);
        $this->assertSame([PersonalAccessToken::findToken($token)?->getKey()], PersonalAccessToken::query()->pluck('id')->all());
    }

    public function test_a_redirect_uri_that_is_not_listed_is_refused_before_the_code_is_spent(): void
    {
        Socialite::shouldReceive('driver')->never();

        $this->postJson(route('uzair.api.token'), $this->exchange(['redirect_uri' => 'https://evil.test/callback']))
            ->assertUnprocessable()
            ->assertJsonValidationErrors('redirect_uri');
    }

    public function test_a_code_without_its_verifier_is_refused(): void
    {
        Socialite::shouldReceive('driver')->never();

        $this->postJson(route('uzair.api.token'), $this->exchange(['code_verifier' => null]))
            ->assertUnprocessable()
            ->assertJsonValidationErrors('code_verifier');
    }

    public function test_a_login_that_cannot_be_recorded_takes_its_sanctum_token_back_and_surrenders_the_grants(): void
    {
        $provider = $this->fakeExchange(['id' => '7002', 'token' => 'sso-access', 'refreshToken' => 'sso-refresh']);
        $provider->shouldReceive('logoutAsync')->with('sso-access')->once()->andReturn($this->revoked());
        $provider->shouldReceive('revokeRefreshTokenAsync')->with('sso-refresh')->once()->andReturn($this->revoked());

        OauthToken::creating(fn (): bool => false);

        $this->postJson(route('uzair.api.token'), $this->exchange())
            ->assertServiceUnavailable()
            ->assertExactJson(['message' => __('uzairid::messages.temporarily_unavailable')]);

        $this->assertSame(0, PersonalAccessToken::query()->count());
        $this->assertSame(0, OauthToken::query()->count());
    }

    public function test_a_failure_after_the_token_is_issued_ends_the_login_the_client_never_received(): void
    {
        $provider = $this->fakeExchange(['id' => '7009', 'token' => 'sso-access', 'refreshToken' => 'sso-refresh']);
        $provider->shouldReceive('logoutAsync')->with('sso-access')->once()->andReturn($this->revoked());
        $provider->shouldReceive('revokeRefreshTokenAsync')->with('sso-refresh')->once()->andReturn($this->revoked());

        Event::listen(UzairAuthenticated::class, function (): void {
            throw new RuntimeException('A listener of the application failed.');
        });

        $this->postJson(route('uzair.api.token'), $this->exchange())
            ->assertServiceUnavailable()
            ->assertExactJson(['message' => __('uzairid::messages.temporarily_unavailable')]);

        $this->assertSame(0, PersonalAccessToken::query()->count());
        $this->assertSame(0, OauthToken::query()->count());
    }

    #[DataProvider('providerFailures')]
    public function test_the_exchange_distinguishes_an_unauthorized_grant_from_an_unavailable_provider(int $providerStatus, ?string $oauthError, int $expectedStatus): void
    {
        Event::fake([UzairAuthenticated::class]);
        $provider = Mockery::mock(UzairportsProvider::class);
        $provider->shouldReceive('userFromCode')->once()->andThrow(new BadResponseException(
            'The provider refused the exchange.',
            new PsrRequest('POST', 'https://sso.test/oauth/token'),
            new PsrResponse($providerStatus, [], json_encode(['error' => $oauthError], JSON_THROW_ON_ERROR)),
        ));
        Socialite::shouldReceive('driver')->with('uzairports')->andReturn($provider);

        $response = $this->postJson(route('uzair.api.token'), $this->exchange());

        $response->assertStatus($expectedStatus)->assertExactJson([
            'message' => $expectedStatus === 401
                ? __('uzairid::messages.authentication_failed')
                : __('uzairid::messages.temporarily_unavailable'),
        ]);
        $this->assertSame(0, SanctumUser::query()->count());
        $this->assertSame(0, PersonalAccessToken::query()->count());
        $this->assertSame(0, OauthToken::query()->count());
        Event::assertNotDispatched(UzairAuthenticated::class);
    }

    /**
     * @return array<string, array{int, string|null, int}>
     */
    public static function providerFailures(): array
    {
        return [
            'invalid grant returns 401' => [400, 'invalid_grant', 401],
            'invalid token returns 401' => [401, 'invalid_token', 401],
            'access denied returns 401' => [403, 'access_denied', 401],
            'unauthorized without an OAuth error returns 401' => [401, null, 401],
            'invalid client returns 503' => [401, 'invalid_client', 503],
            'unauthorized client returns 503' => [400, 'unauthorized_client', 503],
            'invalid request returns 503' => [400, 'invalid_request', 503],
            'rate limited returns 503' => [429, null, 503],
            'provider outage returns 503' => [503, null, 503],
            'server failure with a grant error returns 503' => [500, 'invalid_grant', 503],
        ];
    }

    public function test_a_provider_timeout_returns_503_without_creating_a_login(): void
    {
        $provider = Mockery::mock(UzairportsProvider::class);
        $provider->shouldReceive('userFromCode')->once()->andThrow(new ConnectException(
            'The connection timed out.', new PsrRequest('POST', 'https://sso.test/oauth/token'),
        ));
        Socialite::shouldReceive('driver')->with('uzairports')->andReturn($provider);

        $response = $this->postJson(route('uzair.api.token'), $this->exchange());

        $response->assertServiceUnavailable()->assertExactJson(['message' => __('uzairid::messages.temporarily_unavailable')]);
        $this->assertSame(0, PersonalAccessToken::query()->count());
        $this->assertSame(0, OauthToken::query()->count());
    }

    public function test_a_refused_account_write_returns_503_and_surrenders_the_issued_grants(): void
    {
        Schema::table('users', function (Blueprint $table): void {
            $table->string('required_by_application');
        });
        $provider = $this->fakeExchange(['id' => '7031', 'token' => 'sso-access', 'refreshToken' => 'sso-refresh']);
        $provider->shouldReceive('logoutAsync')->with('sso-access')->once()->andReturn($this->revoked());
        $provider->shouldReceive('revokeRefreshTokenAsync')->with('sso-refresh')->once()->andReturn($this->revoked());

        $response = $this->postJson(route('uzair.api.token'), $this->exchange());

        $response->assertServiceUnavailable()->assertExactJson(['message' => __('uzairid::messages.temporarily_unavailable')]);
        $this->assertSame(0, SanctumUser::query()->count());
        $this->assertSame(0, PersonalAccessToken::query()->count());
        $this->assertSame(0, OauthToken::query()->count());
    }

    public function test_an_explicit_authentication_refusal_returns_401_without_creating_a_login(): void
    {
        $provider = Mockery::mock(UzairportsProvider::class);
        $provider->shouldReceive('userFromCode')->once()->andThrow(new AuthenticationException);
        Socialite::shouldReceive('driver')->with('uzairports')->andReturn($provider);

        $response = $this->postJson(route('uzair.api.token'), $this->exchange());

        $response->assertUnauthorized()->assertExactJson(['message' => __('uzairid::messages.authentication_failed')]);
        $this->assertSame(0, PersonalAccessToken::query()->count());
        $this->assertSame(0, OauthToken::query()->count());
    }

    public function test_each_phone_is_answered_by_its_own_login(): void
    {
        $user = SanctumUser::query()->create(['uzair_id' => '7003']);
        [$firstPhone] = $this->phoneLogin($user, 'first');
        [$secondPhone, $secondLogin] = $this->phoneLogin($user, 'second');

        $this->withToken($secondPhone)->getJson('/api/me')
            ->assertOk()
            ->assertJsonPath('login', $secondLogin->id);

        $this->assertNotSame($firstPhone, $secondPhone);
    }

    public function test_a_phone_is_answered_where_sanctum_lists_no_session_guard(): void
    {
        config(['sanctum.guard' => []]);

        $user = SanctumUser::query()->create(['uzair_id' => '7011']);
        [$plainTextToken, $login] = $this->phoneLogin($user, 'phone');

        $this->withToken($plainTextToken)->getJson('/api/me')
            ->assertOk()
            ->assertJsonPath('login', $login->id);
    }

    public function test_a_phone_whose_login_was_ended_is_refused_and_loses_its_sanctum_token(): void
    {
        $this->acceptsRevocations();

        $user = SanctumUser::query()->create(['uzair_id' => '7004']);
        [$plainTextToken, $login] = $this->phoneLogin($user, 'phone');

        app(EndSessions::class)->end($login);

        $this->assertSame(0, PersonalAccessToken::query()->count());

        $this->withToken($plainTextToken)->getJson('/api/me')->assertUnauthorized();
    }

    public function test_a_phone_signs_itself_out_and_leaves_the_other_phone_alone(): void
    {
        $user = SanctumUser::query()->create(['uzair_id' => '7005']);
        [$plainTextToken, $login] = $this->phoneLogin($user, 'phone', 'phone-access');
        [, $otherLogin] = $this->phoneLogin($user, 'other');

        $provider = Mockery::mock(UzairportsProvider::class);
        $provider->shouldReceive('logoutAsync')->with('phone-access')->once()->andReturn($this->revoked());
        Socialite::shouldReceive('driver')->with('uzairports')->andReturn($provider);

        $this->withToken($plainTextToken)->postJson(route('uzair.api.logout'))->assertNoContent();

        $this->assertModelMissing($login);
        $this->assertModelExists($otherLogin);
        $this->assertNull(PersonalAccessToken::findToken($plainTextToken));
        $this->assertSame(1, PersonalAccessToken::query()->count());
    }

    public function test_a_client_that_sends_no_accept_header_is_still_answered_in_json(): void
    {
        $user = SanctumUser::query()->create(['uzair_id' => '7011']);
        $plainTextToken = $user->createToken('phone')->plainTextToken;

        $this->post(route('uzair.api.token'), $this->exchange(['redirect_uri' => 'https://evil.test/callback']))
            ->assertUnprocessable()
            ->assertJsonValidationErrors('redirect_uri');

        $this->withToken($plainTextToken)->post(route('uzair.api.logout'))->assertNoContent();
    }

    public function test_signing_out_revokes_a_bearer_token_no_login_is_filed_under(): void
    {
        $user = SanctumUser::query()->create(['uzair_id' => '7010']);
        $issuedByTheApplication = $user->createToken('password-login')->plainTextToken;

        $this->withToken($issuedByTheApplication)->postJson(route('uzair.api.logout'))->assertNoContent();

        $this->assertNull(PersonalAccessToken::findToken($issuedByTheApplication));
    }

    public function test_a_login_whose_sanctum_token_is_gone_is_pruned(): void
    {
        $this->acceptsRevocations();

        $user = SanctumUser::query()->create(['uzair_id' => '7006']);
        [, $orphaned] = $this->phoneLogin($user, 'orphaned');
        [, $kept] = $this->phoneLogin($user, 'kept');

        PersonalAccessToken::query()->whereKey($orphaned->personal_access_token_id)->delete();

        $this->assertSame(1, (new OauthToken)->pruneAll());

        $this->assertModelMissing($orphaned);
        $this->assertModelExists($kept);
    }

    #[DataProvider('expiredSanctumTokens')]
    public function test_pruning_an_expired_sanctum_token_removes_its_login_and_surrenders_its_grants(?int $expiresInMinutes, ?int $globalMinutes, int $ageMinutes): void
    {
        $this->freezeSecond();
        config(['sanctum.expiration' => $globalMinutes]);
        $user = SanctumUser::query()->create(['uzair_id' => 'expired-mobile']);
        [, $expired] = $this->phoneLogin($user, 'expired', 'expired-access');
        [, $kept] = $this->phoneLogin($user, 'kept', 'kept-access');
        PersonalAccessToken::query()->whereKey($expired->personal_access_token_id)->update([
            'created_at' => now()->subMinutes($ageMinutes),
            'expires_at' => $expiresInMinutes === null ? null : now()->addMinutes($expiresInMinutes),
        ]);

        $provider = Mockery::mock(UzairportsProvider::class);
        $provider->shouldReceive('logoutAsync')->with('expired-access')->once()->andReturn($this->revoked());
        $provider->shouldReceive('revokeRefreshTokenAsync')->with('sso-refresh')->once()->andReturn($this->revoked());
        Socialite::shouldReceive('driver')->with('uzairports')->andReturn($provider);

        $this->assertSame(1, (new OauthToken)->pruneAll());

        $this->assertModelMissing($expired);
        $this->assertDatabaseMissing('personal_access_tokens', ['id' => $expired->personal_access_token_id]);
        $this->assertModelExists($kept);
        $this->assertDatabaseHas('personal_access_tokens', ['id' => $kept->personal_access_token_id]);
    }

    /**
     * @return array<string, array{int|null, int|null, int}>
     */
    public static function expiredSanctumTokens(): array
    {
        return [
            'individual expiry' => [-1, null, 1],
            'global expiry despite later individual expiry' => [30, 60, 61],
            'exact global age limit without individual expiry' => [null, 60, 60],
            'individual expiry before global expiry' => [-1, 60, 1],
        ];
    }

    #[DataProvider('liveSanctumTokens')]
    public function test_pruning_preserves_a_mobile_login_whose_sanctum_token_has_not_expired(?int $expiresInMinutes, ?int $globalMinutes, int $ageMinutes): void
    {
        $this->freezeSecond();
        config(['sanctum.expiration' => $globalMinutes]);
        Socialite::shouldReceive('driver')->never();
        $user = SanctumUser::query()->create(['uzair_id' => 'live-mobile']);
        [, $login] = $this->phoneLogin($user, 'phone');
        PersonalAccessToken::query()->whereKey($login->personal_access_token_id)->update([
            'created_at' => now()->subMinutes($ageMinutes),
            'expires_at' => $expiresInMinutes === null ? null : now()->addMinutes($expiresInMinutes),
        ]);

        $this->assertSame(0, (new OauthToken)->pruneAll());

        $this->assertModelExists($login);
        $this->assertDatabaseHas('personal_access_tokens', ['id' => $login->personal_access_token_id]);
    }

    /**
     * @return array<string, array{int|null, int|null, int}>
     */
    public static function liveSanctumTokens(): array
    {
        return [
            'no expiration limits' => [null, null, 1440],
            'global expiration disabled' => [null, 0, 1440],
            'future individual expiry' => [30, null, 1440],
            'individual expiry is not past yet' => [0, null, 1],
            'global age limit not reached' => [null, 60, 59],
        ];
    }

    public function test_pruning_preserves_a_mobile_login_rotated_after_its_chunk_was_read(): void
    {
        $this->freezeSecond();
        Socialite::shouldReceive('driver')->never();
        $user = SanctumUser::query()->create(['uzair_id' => 'rotated-during-pruning']);
        [, $login] = $this->phoneLogin($user, 'phone');
        PersonalAccessToken::query()->whereKey($login->personal_access_token_id)->update(['expires_at' => now()->subMinute()]);
        $newToken = $user->createToken('renewed-phone');
        $rotated = false;

        OauthToken::retrieved(function (OauthToken $snapshot) use (&$rotated, $login, $newToken): void {
            if ($rotated || $snapshot->id !== $login->id) {
                return;
            }

            $rotated = true;
            OauthToken::query()->whereKey($login->id)->update(['personal_access_token_id' => $newToken->accessToken->getKey()]);
            PersonalAccessToken::query()->whereKey($login->personal_access_token_id)->delete();
        });

        try {
            $this->assertSame(0, (new OauthToken)->pruneAll());
        } finally {
            OauthToken::flushEventListeners();
        }

        $this->assertTrue($rotated);
        $this->assertDatabaseHas('oauth_tokens', ['id' => $login->id, 'personal_access_token_id' => $newToken->accessToken->getKey()]);
        $this->assertModelExists($newToken->accessToken);
    }

    public function test_the_sanctum_token_and_the_session_tokens_relation_do_not_collide(): void
    {
        $user = SanctumUser::query()->create(['uzair_id' => '7007']);
        $this->phoneLogin($user, 'phone');

        $this->assertInstanceOf(PersonalAccessToken::class, $user->tokens()->sole());
        $this->assertInstanceOf(OauthToken::class, $user->uzairTokens()->sole());
    }

    public function test_refresh_endpoint_rotates_sanctum_token(): void
    {
        $user = SanctumUser::query()->create(['uzair_id' => '7020']);
        [$plainTextToken, $login] = $this->phoneLogin($user, 'phone');

        $response = $this->withToken($plainTextToken)->postJson(route('uzair.api.refresh'));

        $response->assertOk()
            ->assertJsonStructure(['token', 'token_type', 'expires_at']);

        $newToken = $this->issuedToken($response);
        $this->assertNotSame($plainTextToken, $newToken);

        $this->assertNull(PersonalAccessToken::findToken($plainTextToken));

        $foundNew = PersonalAccessToken::findToken($newToken);
        $this->assertNotNull($foundNew);
        $this->assertSame($foundNew->getKey(), $login->fresh()?->personal_access_token_id);
    }

    public function test_refresh_endpoint_refuses_an_overlong_device_name_and_keeps_the_token(): void
    {
        $user = SanctumUser::query()->create(['uzair_id' => '7023']);
        [$plainTextToken] = $this->phoneLogin($user, 'phone');

        $this->withToken($plainTextToken)
            ->postJson(route('uzair.api.refresh'), ['device_name' => str_repeat('a', 256)])
            ->assertUnprocessable()
            ->assertJsonValidationErrors('device_name');

        $this->assertNotNull(PersonalAccessToken::findToken($plainTextToken));
    }

    public function test_refresh_endpoint_requires_authentication(): void
    {
        $this->postJson(route('uzair.api.refresh'))->assertUnauthorized();
    }

    public function test_refresh_returns_503_and_keeps_the_previous_token_when_a_listener_refuses_the_login_write(): void
    {
        $user = SanctumUser::query()->create(['uzair_id' => '7032']);
        [$plainTextToken, $login] = $this->phoneLogin($user, 'phone');
        OauthToken::saving(fn (): bool => false);

        $response = $this->withToken($plainTextToken)->postJson(route('uzair.api.refresh'));

        $response->assertServiceUnavailable()->assertExactJson(['message' => __('uzairid::messages.temporarily_unavailable')]);
        $this->assertDatabaseHas('oauth_tokens', ['id' => $login->id, 'personal_access_token_id' => $login->personal_access_token_id]);
        $this->assertNotNull(PersonalAccessToken::findToken($plainTextToken));
        $this->assertSame(1, PersonalAccessToken::query()->count());
    }

    public function test_refresh_returns_503_and_keeps_the_previous_token_when_a_listener_refuses_the_sanctum_token(): void
    {
        $user = SanctumUser::query()->create(['uzair_id' => '7033']);
        [$plainTextToken, $login] = $this->phoneLogin($user, 'phone');
        PersonalAccessToken::creating(fn (): bool => false);

        $response = $this->withToken($plainTextToken)->postJson(route('uzair.api.refresh'));

        $response->assertServiceUnavailable()->assertExactJson(['message' => __('uzairid::messages.temporarily_unavailable')]);
        $this->assertDatabaseHas('oauth_tokens', ['id' => $login->id, 'personal_access_token_id' => $login->personal_access_token_id]);
        $this->assertNotNull(PersonalAccessToken::findToken($plainTextToken));
        $this->assertSame(1, PersonalAccessToken::query()->count());
    }

    public function test_refresh_returns_503_and_rolls_back_when_the_old_sanctum_token_cannot_be_deleted(): void
    {
        $user = SanctumUser::query()->create(['uzair_id' => 'failed-token-deletion']);
        [$plainTextToken, $login] = $this->phoneLogin($user, 'phone');
        Schema::create('token_references', function (Blueprint $table): void {
            $table->foreignId('personal_access_token_id')->constrained('personal_access_tokens')->restrictOnDelete();
        });
        DB::table('token_references')->insert(['personal_access_token_id' => $login->personal_access_token_id]);

        $response = $this->withToken($plainTextToken)->postJson(route('uzair.api.refresh'));

        $response->assertServiceUnavailable()->assertExactJson(['message' => __('uzairid::messages.temporarily_unavailable')]);
        $this->assertDatabaseHas('oauth_tokens', ['id' => $login->id, 'personal_access_token_id' => $login->personal_access_token_id]);
        $this->assertNotNull(PersonalAccessToken::findToken($plainTextToken));
        $this->assertDatabaseCount('personal_access_tokens', 1);
    }

    #[DataProvider('competingExpirations')]
    public function test_refresh_reports_the_earlier_of_the_new_token_and_sanctums_expiration(int $tokenMinutes, int $sanctumMinutes): void
    {
        $this->freezeSecond();
        config(['uzairports.api.token_expiration' => $tokenMinutes, 'sanctum.expiration' => $sanctumMinutes]);
        $user = SanctumUser::query()->create(['uzair_id' => '7034']);
        [$plainTextToken, $login] = $this->phoneLogin($user, 'phone');

        $response = $this->withToken($plainTextToken)->postJson(route('uzair.api.refresh'));

        $response->assertOk()->assertJsonPath('expires_at', now()->addMinutes(30)->toIso8601String());
        $accessToken = PersonalAccessToken::findToken($this->issuedToken($response));
        $this->assertNotNull($accessToken);
        $this->assertSame($accessToken->getKey(), $login->fresh()?->personal_access_token_id);
        $this->assertNull(PersonalAccessToken::findToken($plainTextToken));
    }

    public function test_mobile_login_with_expired_access_and_no_refresh_is_not_pruned_while_sanctum_token_exists(): void
    {
        $user = SanctumUser::query()->create(['uzair_id' => '7021']);
        [, $phoneLogin] = $this->phoneLogin($user, 'phone');

        $phoneLogin->forceFill([
            'refresh_token' => null,
            'expires_at' => now()->subMinute(),
        ])->save();

        $this->assertSame(0, (new OauthToken)->prunable()->count());

        PersonalAccessToken::query()->whereKey($phoneLogin->personal_access_token_id)->delete();

        $this->assertSame(1, (new OauthToken)->prunable()->count());
    }

    /**
     * A grant the identity provider refused is dead whatever ending its row
     * costs. Ending it used to sit in the same `try` as the rotation, so a
     * failure there answered 503 and the client retried a dead grant forever.
     */
    public function test_refresh_answers_401_for_a_refused_grant_even_when_its_login_cannot_be_ended(): void
    {
        $user = SanctumUser::query()->create(['uzair_id' => '7024']);
        [$plainTextToken, $login] = $this->phoneLogin($user, 'phone');
        $login->forceFill(['expires_at' => now()->subMinute()])->save();

        $this->mock(RefreshAccessToken::class)->shouldReceive('__invoke')->once()->andReturnFalse();
        $this->mock(EndSessions::class)->shouldReceive('end')->once()->andThrow(new RuntimeException('The database went away.'));
        Log::shouldReceive('warning')
            ->with('Failed to end an UzAirports login whose grant could no longer be renewed.', ['exception_class' => RuntimeException::class])
            ->once();

        $this->withToken($plainTextToken)
            ->postJson(route('uzair.api.refresh'))
            ->assertUnauthorized()
            ->assertExactJson(['message' => __('uzairid::messages.session_expired')]);
    }

    public function test_refresh_endpoint_returns_unauthorized_when_token_was_already_rotated(): void
    {
        $user = SanctumUser::query()->create(['uzair_id' => '7022']);
        [$plainTextToken, $login] = $this->phoneLogin($user, 'phone');

        // Simulate another concurrent request having rotated the personal_access_token_id
        $login->forceFill(['personal_access_token_id' => 999999])->save();

        $response = $this->withToken($plainTextToken)->postJson(route('uzair.api.refresh'));

        $response->assertUnauthorized()
            ->assertJsonPath('message', __('uzairid::messages.session_ended'));
    }

    /**
     * The plain-text Sanctum token an exchange answered with.
     *
     * @param  TestResponse<Response>  $response
     */
    private function issuedToken(TestResponse $response): string
    {
        $token = $response->json('token');

        $this->assertIsString($token);

        return $token;
    }

    /**
     * The fields a mobile client posts once it holds a code.
     *
     * @param  array<string, string|null>  $overrides
     * @return array<string, string|null>
     */
    private function exchange(array $overrides = []): array
    {
        return array_merge([
            'code' => 'code-from-the-app',
            'redirect_uri' => self::REDIRECT_URI,
            'code_verifier' => self::VERIFIER,
            'device_name' => 'Pixel 9',
        ], $overrides);
    }

    /**
     * @param  array<string, mixed>  $identity
     */
    private function fakeExchange(array $identity): MockInterface
    {
        $provider = Mockery::mock(UzairportsProvider::class);
        $provider->shouldReceive('userFromCode')->andReturn(SocialiteUser::fake($identity));

        Socialite::shouldReceive('driver')->with('uzairports')->andReturn($provider);

        return $provider;
    }

    /**
     * A phone already signed in: its Sanctum token and the login filed under it.
     *
     * @return array{0: string, 1: OauthToken}
     */
    private function phoneLogin(SanctumUser $user, string $name, string $accessToken = 'sso-access'): array
    {
        $issued = $user->createToken($name);

        $login = (new OauthToken)->forceFill([
            'user_id' => $user->getKey(),
            'personal_access_token_id' => $issued->accessToken->getKey(),
            'access_token' => $accessToken,
            'refresh_token' => 'sso-refresh',
            'expires_at' => now()->addHour(),
        ]);
        $login->save() || throw new RuntimeException('The login was not written.');

        return [$issued->plainTextToken, $login];
    }
}

/**
 * An account carrying both traits, the way the documentation tells an
 * application to: Sanctum keeps `tokens()`, the logins are `uzairTokens()`.
 *
 * @property int $id
 * @property string|null $uzair_id
 */
class SanctumUser extends Authenticatable
{
    use HasApiTokens, HasUzairToken {
        HasApiTokens::tokens insteadof HasUzairToken;
    }

    protected $table = 'users';

    protected $guarded = [];
}
