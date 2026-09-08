<?php

namespace Uzairports\Uzairid\Tests;

use Exception;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\UniqueConstraintViolationException;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Str;
use Laravel\Socialite\Facades\Socialite;
use Laravel\Socialite\Two\InvalidStateException;
use Laravel\Socialite\Two\User as SocialiteUser;
use Mockery;
use RuntimeException;
use Throwable;
use Uzairports\Uzairid\Actions\ResolveUserFromSocialite;
use Uzairports\Uzairid\Events\UzairAuthenticated;
use Uzairports\Uzairid\Events\UzairLoggedOut;
use Uzairports\Uzairid\Models\OauthToken;
use Uzairports\Uzairid\Socialite\UzairportsProvider;

class UzairAuthControllerTest extends TestCase
{
    protected function tearDown(): void
    {
        Mockery::close();

        parent::tearDown();
    }

    public function test_the_callback_opens_a_session_and_stores_the_login(): void
    {
        Event::fake([UzairAuthenticated::class]);

        $this->fakeIdentity([
            'id' => '5001',
            'name' => 'Captain Pilot',
            'email' => 'pilot@uzairports.com',
            'token' => 'access_token_value',
            'refreshToken' => 'refresh_token_value',
            'expiresIn' => 3600,
        ]);

        $this->get(route('uzair.callback'))->assertRedirect(route('dashboard'));

        $this->assertAuthenticated();

        $user = TestUser::query()->firstWhere('uzair_id', '5001');

        $this->assertNotNull($user);

        $token = $user->tokens()->firstOrFail();

        $this->assertSame('access_token_value', $token->access_token);
        $this->assertNotNull($token->session_id);
        $this->assertSame(session()->getId(), $token->session_id);
        $this->assertEqualsWithDelta(3600, now()->diffInSeconds($token->expires_at), 5);

        Event::assertDispatched(UzairAuthenticated::class);
    }

    public function test_the_login_records_the_device_it_was_made_from(): void
    {
        $this->fakeIdentity(['id' => '5002', 'name' => 'Phone', 'token' => 'access_token_value']);

        $this->withServerVariables(['REMOTE_ADDR' => '10.1.2.3'])
            ->withHeaders(['User-Agent' => 'Mozilla/5.0 (iPhone) Safari/605'])
            ->get(route('uzair.callback'))
            ->assertRedirect(route('dashboard'));

        $token = OauthToken::query()->firstOrFail();

        $this->assertSame('10.1.2.3', $token->ip_address);
        $this->assertSame('Safari — iPhone', $token->deviceLabel());
    }

    /**
     * The point of the whole design: a phone and a desktop are two logins, each
     * with the grant its own browser was issued.
     */
    public function test_a_second_device_gets_its_own_login(): void
    {
        $user = TestUser::create(['uzair_id' => '5003', 'name' => 'Two Devices']);
        $user->tokens()->create([
            'access_token' => 'the_first_devices_token',
            'session_id' => 'the-first-devices-session',
        ]);

        $this->fakeIdentity(['id' => '5003', 'name' => 'Two Devices', 'token' => 'the_second_devices_token']);

        $this->get(route('uzair.callback'))->assertRedirect(route('dashboard'));

        $this->assertSame(2, $user->tokens()->count());
        $this->assertEqualsCanonicalizing(
            ['the_first_devices_token', 'the_second_devices_token'],
            $user->tokens()->get()->pluck('access_token')->all(),
        );
    }

    /**
     * Regenerating the session renames the login, so running the flow twice in
     * one browser must not leave the first row behind.
     */
    public function test_signing_in_again_on_the_same_device_replaces_that_login(): void
    {
        $this->fakeIdentity(['id' => '5004', 'name' => 'Same Device', 'token' => 'access_token_value'], times: 2);

        $this->get(route('uzair.callback'))->assertRedirect(route('dashboard'));

        $this->onTheDeviceHolding(OauthToken::query()->firstOrFail())
            ->get(route('uzair.callback'))
            ->assertRedirect(route('dashboard'));

        $this->assertSame(1, OauthToken::query()->count());
    }

    public function test_single_session_ends_the_accounts_other_logins(): void
    {
        config(['uzairports.single_session' => true, 'session.driver' => 'database']);

        $user = TestUser::create(['uzair_id' => '5005', 'name' => 'Exclusive']);
        $user->tokens()->create([
            'access_token' => 'the_first_devices_token',
            'session_id' => 'the-first-devices-session',
        ]);

        DB::table('sessions')->insert([
            'id' => 'the-first-devices-session',
            'user_id' => $user->getKey(),
            'payload' => '',
            'last_activity' => now()->getTimestamp(),
        ]);

        $provider = Mockery::mock(UzairportsProvider::class);
        $provider->shouldReceive('user')->once()->andReturn(SocialiteUser::fake([
            'id' => '5005',
            'name' => 'Exclusive',
            'token' => 'the_second_devices_token',
        ]));
        $provider->shouldReceive('logout')->with('the_first_devices_token')->once();

        Socialite::shouldReceive('driver')->with('uzairports')->andReturn($provider);

        $this->get(route('uzair.callback'))->assertRedirect(route('dashboard'));

        $this->assertSame(1, $user->tokens()->count());
        $this->assertSame('the_second_devices_token', $user->tokens()->firstOrFail()->access_token);
        $this->assertSame(0, DB::table('sessions')->where('id', 'the-first-devices-session')->count());
    }

    public function test_a_failed_handshake_leaves_no_session_and_no_rows_behind(): void
    {
        $provider = Mockery::mock(UzairportsProvider::class);
        $provider->shouldReceive('user')->once()->andThrow(new Exception('Invalid OAuth code'));

        Socialite::shouldReceive('driver')->with('uzairports')->andReturn($provider);

        $response = $this->get(route('uzair.callback'));

        $response->assertRedirect(url('/'));
        $response->assertSessionHasErrors('oauth');

        $this->assertGuest();
        $this->assertSame(0, TestUser::query()->count());
        $this->assertSame(0, OauthToken::query()->count());
    }

    public function test_a_callback_with_an_error_parameter_is_handled_gracefully(): void
    {
        Socialite::shouldReceive('driver')->never();

        $response = $this->get(route('uzair.callback', [
            'error' => 'access_denied',
            'error_description' => 'User cancelled authorization',
        ]));

        $response->assertRedirect(url('/'));
        $response->assertSessionHasErrors(['oauth' => __('uzairid::messages.authentication_failed')]);

        $this->assertGuest();
    }

    /**
     * The session that held the handshake's state was lost between the redirect
     * and the callback, or the flow was started twice and finished on the older
     * one. Nothing is wrong with the account, so the user is told to start over
     * rather than that authentication failed.
     */
    public function test_a_handshake_that_lost_its_state_is_reported_as_such(): void
    {
        $provider = Mockery::mock(UzairportsProvider::class);
        $provider->shouldReceive('user')->once()->andThrow(new InvalidStateException);

        Socialite::shouldReceive('driver')->with('uzairports')->andReturn($provider);

        $response = $this->get(route('uzair.callback'));

        $response->assertRedirect(url('/'));
        $response->assertSessionHasErrors(['oauth' => __('uzairid::messages.handshake_lost')]);

        $this->assertGuest();
    }

    /**
     * A browser that sent no session cookie never had one to send, which is a
     * host mismatch rather than a stale tab — and the log has to say which.
     */
    public function test_a_lost_handshake_records_whether_a_session_cookie_came_back(): void
    {
        Log::shouldReceive('warning')
            ->once()
            ->withArgs(fn (string $message, array $context): bool => $context['session_cookie_received'] === false
                && $context['callback_host'] === url('/'));

        $provider = Mockery::mock(UzairportsProvider::class);
        $provider->shouldReceive('user')->once()->andThrow(new InvalidStateException);

        Socialite::shouldReceive('driver')->with('uzairports')->andReturn($provider);

        $this->get(route('uzair.callback'))->assertRedirect(url('/'));
    }

    /**
     * `InvalidStateException` carries no message, which used to leave the log
     * line reading "callback failed": and nothing else.
     */
    public function test_a_failure_carrying_no_message_is_logged_by_its_class(): void
    {
        Log::shouldReceive('error')
            ->once()
            ->withArgs(fn (string $message): bool => str_contains($message, 'RuntimeException'));

        $provider = Mockery::mock(UzairportsProvider::class);
        $provider->shouldReceive('user')->once()->andThrow(new RuntimeException);

        Socialite::shouldReceive('driver')->with('uzairports')->andReturn($provider);

        $this->get(route('uzair.callback'))->assertRedirect(url('/'));
    }

    /**
     * Two callbacks for an identity with no local account, yet both see nothing
     * to update and both insert. The loser's transaction is rolled back by the
     * unique index on `users.uzair_id`, and the work is done again — this time
     * finding the row the winner wrote.
     */
    public function test_a_callback_that_loses_the_race_to_create_the_account_retries(): void
    {
        $this->instance(ResolveUserFromSocialite::class, new ResolverLosingTheFirstRace);

        $this->fakeIdentity(['id' => '5006', 'name' => 'Racer', 'token' => 'access_token_value']);

        $this->get(route('uzair.callback'))->assertRedirect(route('dashboard'));

        $this->assertAuthenticated();
        $this->assertSame(1, TestUser::query()->where('uzair_id', '5006')->count());
        $this->assertSame(1, OauthToken::query()->count());
    }

    public function test_logout_ends_this_device_only(): void
    {
        Event::fake([UzairLoggedOut::class]);

        $user = TestUser::create(['uzair_id' => '5007', 'name' => 'Leaving']);
        $user->tokens()->create([
            'access_token' => 'the_other_devices_token',
            'session_id' => 'the-other-devices-session',
        ]);

        $this->fakeIdentity(['id' => '5007', 'name' => 'Leaving', 'token' => 'this_devices_token'], logout: 'this_devices_token');

        $this->get(route('uzair.callback'))->assertRedirect(route('dashboard'));

        $thisDevice = $user->tokens()->where('session_id', '!=', 'the-other-devices-session')->firstOrFail();

        $this->onTheDeviceHolding($thisDevice)->post(route('uzair.logout'))->assertRedirect(url('/'));

        $this->assertGuest();
        $this->assertSame(['the-other-devices-session'], $user->tokens()->pluck('session_id')->all());

        Event::assertDispatched(UzairLoggedOut::class);
    }

    public function test_logout_all_ends_every_device(): void
    {
        $user = TestUser::create(['uzair_id' => '5008', 'name' => 'Leaving Everywhere']);
        $user->tokens()->create([
            'access_token' => 'the_other_devices_token',
            'session_id' => 'the-other-devices-session',
        ]);

        $provider = Mockery::mock(UzairportsProvider::class);
        $provider->shouldReceive('user')->once()->andReturn(SocialiteUser::fake([
            'id' => '5008',
            'name' => 'Leaving Everywhere',
            'token' => 'this_devices_token',
        ]));
        $provider->shouldReceive('logout')->with('this_devices_token')->once();
        $provider->shouldReceive('logout')->with('the_other_devices_token')->once();

        Socialite::shouldReceive('driver')->with('uzairports')->andReturn($provider);

        $this->get(route('uzair.callback'))->assertRedirect(route('dashboard'));

        $thisDevice = $user->tokens()->where('session_id', '!=', 'the-other-devices-session')->firstOrFail();

        $this->onTheDeviceHolding($thisDevice)->post(route('uzair.logoutAll'))->assertRedirect(url('/'));

        $this->assertGuest();
        $this->assertSame(0, $user->tokens()->count());
    }

    public function test_logout_survives_an_unreachable_identity_provider(): void
    {
        $user = TestUser::create(['uzair_id' => '5009', 'name' => 'Failover']);

        $this->fakeIdentity(['id' => '5009', 'name' => 'Failover', 'token' => 'faulty_token']);

        $this->get(route('uzair.callback'))->assertRedirect(route('dashboard'));

        $this->onTheDeviceHolding($user->tokens()->firstOrFail())
            ->post(route('uzair.logout'))
            ->assertRedirect(url('/'));

        $this->assertGuest();
        $this->assertSame(0, $user->tokens()->count());
    }

    public function test_logout_answers_an_api_client_with_204(): void
    {
        $user = TestUser::create(['uzair_id' => '5010', 'name' => 'Api Client']);

        $this->actingAs($user)->postJson(route('uzair.logout'))->assertStatus(204);

        $this->assertGuest();
    }

    /**
     * What a list of "your devices" needs: ending one of them from another,
     * without signing the browser doing the ending out.
     */
    public function test_one_of_the_accounts_other_devices_can_be_ended(): void
    {
        $user = TestUser::create(['uzair_id' => '5011', 'name' => 'Two Devices']);

        $theOtherDevice = $user->tokens()->create([
            'access_token' => 'the_other_devices_token',
            'session_id' => 'the-other-devices-session',
        ]);

        $this->fakeIdentity(
            ['id' => '5011', 'name' => 'Two Devices', 'token' => 'this_devices_token'],
            logout: 'the_other_devices_token',
        );

        $this->get(route('uzair.callback'))->assertRedirect(route('dashboard'));

        $thisDevice = $user->tokens()->where('session_id', '!=', 'the-other-devices-session')->firstOrFail();

        $this->onTheDeviceHolding($thisDevice)
            ->from(route('dashboard'))
            ->post(route('uzair.logoutDevice', $theOtherDevice))
            ->assertRedirect(route('dashboard'));

        $this->assertAuthenticated();
        $this->assertSame([$thisDevice->session_id], $user->tokens()->pluck('session_id')->all());
    }

    /**
     * Ending the login you are running on is signing yourself out, and has to
     * take the session with it rather than leave a browser authenticated
     * against a row that no longer exists.
     */
    public function test_ending_this_devices_own_login_signs_it_out(): void
    {
        $user = TestUser::create(['uzair_id' => '5012', 'name' => 'Leaving Here']);

        $this->fakeIdentity(['id' => '5012', 'name' => 'Leaving Here', 'token' => 'this_devices_token'], logout: 'this_devices_token');

        $this->get(route('uzair.callback'))->assertRedirect(route('dashboard'));

        $thisDevice = $user->tokens()->firstOrFail();

        $this->onTheDeviceHolding($thisDevice)
            ->post(route('uzair.logoutDevice', $thisDevice))
            ->assertRedirect(url('/'));

        $this->assertGuest();
        $this->assertSame(0, $user->tokens()->count());
    }

    /**
     * Someone else's login is not refused but simply not found, so the endpoint
     * cannot be used to learn which rows exist.
     */
    public function test_another_accounts_login_cannot_be_ended(): void
    {
        $user = TestUser::create(['uzair_id' => '5013', 'name' => 'Curious']);
        $bystander = TestUser::create(['uzair_id' => '5014', 'name' => 'Bystander']);

        $theirs = $bystander->tokens()->create([
            'access_token' => 'someone_elses_token',
            'session_id' => 'someone-elses-session',
        ]);

        $this->actingAs($user)
            ->post(route('uzair.logoutDevice', $theirs))
            ->assertNotFound();

        $this->assertSame(1, $bystander->tokens()->count());
    }

    /**
     * A login names itself by its row id, which is always an integer. Letting
     * anything else through would compare a word against a `bigint` column —
     * nothing found on SQLite and MySQL, a type error and a 500 on PostgreSQL.
     */
    public function test_a_login_named_by_something_that_is_not_a_row_id_is_not_found(): void
    {
        $user = TestUser::create(['uzair_id' => '5016', 'name' => 'Guessing']);

        $this->actingAs($user)
            ->post('auth/logout-device/not-a-row-id')
            ->assertNotFound();
    }

    public function test_ending_a_device_answers_an_api_client_with_204(): void
    {
        $user = TestUser::create(['uzair_id' => '5015', 'name' => 'Api Client']);

        $theOtherDevice = $user->tokens()->create([
            'access_token' => 'the_other_devices_token',
            'session_id' => 'the-other-devices-session',
        ]);

        $provider = Mockery::mock(UzairportsProvider::class);
        $provider->shouldReceive('logout')->with('the_other_devices_token')->once();
        Socialite::shouldReceive('driver')->with('uzairports')->andReturn($provider);

        $this->actingAs($user)
            ->postJson(route('uzair.logoutDevice', $theOtherDevice))
            ->assertStatus(204);

        $this->assertAuthenticated();
        $this->assertSame(0, $user->tokens()->count());
    }

    /**
     * The SSO endpoints are unauthenticated and each callback costs a round
     * trip to the identity provider, so they are registered behind a limit.
     */
    public function test_the_endpoints_are_rate_limited(): void
    {
        config(['uzairports.routes.throttle' => '2,1']);

        $this->fromTheBrowser(Str::random(40));

        $this->get(route('login'))->assertStatus(302);
        $this->get(route('login'))->assertStatus(302);
        $this->get(route('login'))->assertStatus(429);
    }

    /**
     * The budget is spent per browser. An office behind one NAT gateway is a
     * single address, so counting it per address would let one colleague lock
     * out the rest.
     */
    public function test_the_limit_is_not_shared_between_browsers(): void
    {
        config(['uzairports.routes.throttle' => '2,1']);

        $this->fromTheBrowser(Str::random(40));
        $this->get(route('login'));
        $this->get(route('login'));
        $this->get(route('login'))->assertStatus(429);

        $this->fromTheBrowser(Str::random(40));
        $this->get(route('login'))->assertStatus(302);
    }

    public function test_the_limit_can_be_lifted(): void
    {
        config(['uzairports.routes.throttle' => null]);

        $this->fromTheBrowser(Str::random(40));

        for ($attempt = 1; $attempt <= 30; $attempt++) {
            $this->get(route('login'))->assertStatus(302);
        }
    }

    /**
     * Carry a session cookie so a run of requests is one browser, the way a
     * real one would be.
     */
    private function fromTheBrowser(string $sessionId): void
    {
        $this->withCookie($this->sessionCookie(), $sessionId);
    }

    /**
     * Carry the session cookie the way the browser holding this login would.
     */
    private function onTheDeviceHolding(OauthToken $token): static
    {
        return $this->withCookie($this->sessionCookie(), (string) $token->session_id);
    }

    /**
     * The name of the cookie a browser is recognised by.
     */
    private function sessionCookie(): string
    {
        $cookie = config('session.cookie');

        if (! is_string($cookie)) {
            throw new RuntimeException('The session cookie has no name, so no browser can be spoken for.');
        }

        return $cookie;
    }

    /**
     * @param array<string, mixed> $attributes
     * @throws Throwable
     */
    private function fakeIdentity(array $attributes, int $times = 1, ?string $logout = null): void
    {
        $provider = Mockery::mock(UzairportsProvider::class);
        $provider->shouldReceive('user')->times($times)->andReturn(SocialiteUser::fake($attributes));

        if ($logout !== null) {
            $provider->shouldReceive('logout')->with($logout)->once();
        } else {
            $provider->shouldReceive('logout')->andReturnNull();
        }

        Socialite::shouldReceive('driver')->with('uzairports')->andReturn($provider);
    }
}

/**
 * Stands in for a second callback that inserted the account first.
 */
class ResolverLosingTheFirstRace extends ResolveUserFromSocialite
{
    private bool $raced = false;

    public function __invoke(SocialiteUser $uzairUser): Model
    {
        if (! $this->raced) {
            $this->raced = true;

            TestUser::create([
                'uzair_id' => (string) $uzairUser->getId(),
                'name' => $uzairUser->getName(),
                'email' => $uzairUser->getEmail(),
            ]);

            throw new UniqueConstraintViolationException(
                'testing',
                'insert into "users" ("uzair_id") values (?)',
                [$uzairUser->getId()],
                new Exception('UNIQUE constraint failed: users.uzair_id'),
            );
        }

        return parent::__invoke($uzairUser);
    }
}
