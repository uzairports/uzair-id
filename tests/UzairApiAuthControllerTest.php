<?php

namespace Uzairports\Uzairid\Tests;

use Illuminate\Foundation\Application;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Http\Request;
use Illuminate\Routing\Router;
use Illuminate\Support\Facades\Event;
use Illuminate\Testing\TestResponse;
use Laravel\Sanctum\HasApiTokens;
use Laravel\Sanctum\PersonalAccessToken;
use Laravel\Sanctum\SanctumServiceProvider;
use Laravel\Socialite\Facades\Socialite;
use Laravel\Socialite\Two\User as SocialiteUser;
use Mockery;
use Mockery\MockInterface;
use RuntimeException;
use Symfony\Component\HttpFoundation\Response;
use Uzairports\Uzairid\Actions\EndSessions;
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

    public function test_a_code_without_its_verifier_is_refused_while_pkce_is_on(): void
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

        $this->postJson(route('uzair.api.token'), $this->exchange())->assertUnauthorized();

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

        $this->postJson(route('uzair.api.token'), $this->exchange())->assertUnauthorized();

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

    public function test_the_sanctum_token_and_the_session_tokens_relation_do_not_collide(): void
    {
        $user = SanctumUser::query()->create(['uzair_id' => '7007']);
        $this->phoneLogin($user, 'phone');

        $this->assertInstanceOf(PersonalAccessToken::class, $user->tokens()->sole());
        $this->assertInstanceOf(OauthToken::class, $user->uzairTokens()->sole());
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
