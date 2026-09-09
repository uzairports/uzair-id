<?php

namespace Uzairports\Uzairid\Tests;

use Exception;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Support\Facades\DB;
use Laravel\Socialite\Facades\Socialite;
use Mockery;
use Uzairports\Uzairid\Actions\EndSessions;
use Uzairports\Uzairid\Models\OauthToken;
use Uzairports\Uzairid\Socialite\UzairportsProvider;

class EndSessionsTest extends TestCase
{
    protected function tearDown(): void
    {
        Mockery::close();

        parent::tearDown();
    }

    public function test_every_login_is_revoked_and_dropped(): void
    {
        config(['session.driver' => 'database']);

        $user = TestUser::create(['uzair_id' => '7001']);
        $this->login($user, 'phone-session', 'phone_token');
        $this->login($user, 'desktop-session', 'desktop_token');

        $provider = Mockery::mock(UzairportsProvider::class);
        $provider->shouldReceive('logout')->with('phone_token')->once();
        $provider->shouldReceive('logout')->with('desktop_token')->once();

        Socialite::shouldReceive('driver')->with('uzairports')->andReturn($provider);

        $ended = (new EndSessions)($user->id);

        $this->assertSame(2, $ended);
        $this->assertSame(0, OauthToken::query()->count());
        $this->assertSame([], $this->storedSessionIds());
    }

    /**
     * There is nothing here to hand over: the row holds a grant this
     * application cannot open, so the identity provider is told nothing and the
     * login ends locally. It used to raise the decryption failure out of the
     * logout the user asked for, leaving them signed in with a 500.
     */
    public function test_a_login_whose_grant_will_not_open_ends_without_asking_the_provider(): void
    {
        $user = TestUser::create(['uzair_id' => '7011']);

        $token = $user->tokens()->create([
            'access_token' => 'a_token',
            'refresh_token' => 'a_refresh_token',
            'session_id' => 'a-session',
        ]);

        DB::table('oauth_tokens')->where('id', $token->id)->update([
            'access_token' => 'not-a-value-this-key-can-open',
            'refresh_token' => 'not-a-value-this-key-can-open',
        ]);

        $stored = $token->fresh();

        $this->assertNotNull($stored);

        Socialite::shouldReceive('driver')->never();

        (new EndSessions)->end($stored);

        $this->assertModelMissing($token);
    }

    public function test_one_login_can_be_spared(): void
    {
        config(['session.driver' => 'database']);

        $user = TestUser::create(['uzair_id' => '7002']);
        $this->login($user, 'phone-session', 'phone_token');
        $this->login($user, 'desktop-session', 'desktop_token');

        $provider = Mockery::mock(UzairportsProvider::class);
        $provider->shouldReceive('logout')->with('phone_token')->once();
        $provider->shouldNotReceive('logout')->with('desktop_token');

        Socialite::shouldReceive('driver')->with('uzairports')->andReturn($provider);

        $ended = (new EndSessions)($user->id, 'desktop-session');

        $this->assertSame(1, $ended);
        $this->assertSame(['desktop-session'], OauthToken::query()->pluck('session_id')->all());
        $this->assertSame(['desktop-session'], $this->storedSessionIds());
    }

    public function test_login_with_null_session_is_ended_when_another_is_spared(): void
    {
        config(['session.driver' => 'database']);

        $user = TestUser::create(['uzair_id' => '70021']);
        $user->tokens()->create([
            'access_token' => 'cli_token',
            'session_id' => null,
        ]);
        $this->login($user, 'desktop-session', 'desktop_token');

        $provider = Mockery::mock(UzairportsProvider::class);
        $provider->shouldReceive('logout')->with('cli_token')->once();
        $provider->shouldNotReceive('logout')->with('desktop_token');

        Socialite::shouldReceive('driver')->with('uzairports')->andReturn($provider);

        $ended = (new EndSessions)($user->id, 'desktop-session');

        $this->assertSame(1, $ended);
        $this->assertSame(['desktop-session'], OauthToken::query()->pluck('session_id')->all());
    }

    public function test_other_accounts_are_left_alone(): void
    {
        config(['session.driver' => 'database']);

        $user = TestUser::create(['uzair_id' => '7003']);
        $bystander = TestUser::create(['uzair_id' => '7004']);

        $this->login($user, 'their-session', 'their_token');
        $this->login($bystander, 'someone-elses-session', 'someone_elses_token');

        $provider = Mockery::mock(UzairportsProvider::class);
        $provider->shouldReceive('logout')->with('their_token')->once();

        Socialite::shouldReceive('driver')->with('uzairports')->andReturn($provider);

        (new EndSessions)($user->id);

        $this->assertSame(['someone-elses-session'], OauthToken::query()->pluck('session_id')->all());
        $this->assertSame(['someone-elses-session'], $this->storedSessionIds());
    }

    /**
     * The identity provider does not get to keep a user signed in here by being
     * unreachable.
     */
    public function test_a_refused_revocation_still_drops_the_login(): void
    {
        $user = TestUser::create(['uzair_id' => '7005']);
        $this->login($user, 'phone-session', 'phone_token');

        $provider = Mockery::mock(UzairportsProvider::class);
        $provider->shouldReceive('logout')->once()->andThrow(new Exception('SSO service unavailable'));

        Socialite::shouldReceive('driver')->with('uzairports')->andReturn($provider);

        (new EndSessions)($user->id);

        $this->assertSame(0, OauthToken::query()->count());
    }

    /**
     * Only the database driver keeps sessions somewhere this can reach. The rows
     * are gone either way, which is what the middleware reads.
     */
    public function test_a_session_store_that_cannot_be_reached_is_left_alone(): void
    {
        config(['session.driver' => 'file']);

        $user = TestUser::create(['uzair_id' => '7006']);
        $this->login($user, 'phone-session', 'phone_token');

        $provider = Mockery::mock(UzairportsProvider::class);
        $provider->shouldReceive('logout')->once();

        Socialite::shouldReceive('driver')->with('uzairports')->andReturn($provider);

        (new EndSessions)($user->id);

        $this->assertSame(0, OauthToken::query()->count());
        $this->assertSame(['phone-session'], $this->storedSessionIds());
    }

    /**
     * Nothing in OAuth promises that retiring an access token retires the
     * refresh token issued with it, and one that outlives the logout is a way
     * back into the account.
     */
    public function test_the_refresh_token_is_given_up_as_well(): void
    {
        $user = TestUser::create(['uzair_id' => '7007']);

        $user->tokens()->create([
            'access_token' => 'phone_token',
            'refresh_token' => 'phone_refresh_token',
            'session_id' => 'phone-session',
        ]);

        $provider = Mockery::mock(UzairportsProvider::class);
        $provider->shouldReceive('logout')->with('phone_token')->once();
        $provider->shouldReceive('revokeRefreshToken')->with('phone_refresh_token')->once();

        Socialite::shouldReceive('driver')->with('uzairports')->andReturn($provider);

        (new EndSessions)($user->id);

        $this->assertSame(0, OauthToken::query()->count());
    }

    /**
     * The two are surrendered independently, so a provider that refuses one
     * still hears about the other.
     */
    public function test_a_refused_access_token_does_not_spare_the_refresh_token(): void
    {
        $user = TestUser::create(['uzair_id' => '7008']);

        $user->tokens()->create([
            'access_token' => 'phone_token',
            'refresh_token' => 'phone_refresh_token',
            'session_id' => 'phone-session',
        ]);

        $provider = Mockery::mock(UzairportsProvider::class);
        $provider->shouldReceive('logout')->once()->andThrow(new Exception('SSO service unavailable'));
        $provider->shouldReceive('revokeRefreshToken')->with('phone_refresh_token')->once();

        Socialite::shouldReceive('driver')->with('uzairports')->andReturn($provider);

        (new EndSessions)($user->id);

        $this->assertSame(0, OauthToken::query()->count());
    }

    public function test_ending_single_token_drops_its_stored_session(): void
    {
        config(['session.driver' => 'database']);

        $user = TestUser::create(['uzair_id' => '7009']);
        $this->login($user, 'device-one-session', 'token_one');
        $this->login($user, 'device-two-session', 'token_two');

        $tokenOne = $user->tokens()->where('session_id', 'device-one-session')->firstOrFail();

        $provider = Mockery::mock(UzairportsProvider::class);
        $provider->shouldReceive('logout')->with('token_one')->once();

        Socialite::shouldReceive('driver')->with('uzairports')->andReturn($provider);

        (new EndSessions)->end($tokenOne);

        $this->assertSame(1, OauthToken::query()->count());
        $this->assertSame(['device-two-session'], $this->storedSessionIds());
    }

    /**
     * The remote surrender is the only part of ending a login that costs a
     * round-trip, and it is the only part that can be given up. What signs the
     * device out here — the row and the stored session — goes either way.
     */
    public function test_logins_end_without_a_remote_call_when_revocation_is_declined(): void
    {
        config(['session.driver' => 'database']);

        $user = TestUser::create(['uzair_id' => '7010']);
        $this->login($user, 'phone-session', 'phone_token');
        $this->login($user, 'desktop-session', 'desktop_token');

        Socialite::shouldReceive('driver')->never();

        $ended = (new EndSessions)($user->id, revoke: false);

        $this->assertSame(2, $ended);
        $this->assertSame(0, OauthToken::query()->count());
        $this->assertSame([], $this->storedSessionIds());
    }

    /**
     * Declining revocation must not become "spare that login": the browser the
     * caller asked to keep is still the only one left standing.
     */
    public function test_declining_revocation_still_spares_the_named_session(): void
    {
        config(['session.driver' => 'database']);

        $user = TestUser::create(['uzair_id' => '7011']);
        $this->login($user, 'phone-session', 'phone_token');
        $this->login($user, 'desktop-session', 'desktop_token');

        Socialite::shouldReceive('driver')->never();

        $ended = (new EndSessions)($user->id, 'desktop-session', revoke: false);

        $this->assertSame(1, $ended);
        $this->assertSame(['desktop-session'], OauthToken::query()->pluck('session_id')->all());
        $this->assertSame(['desktop-session'], $this->storedSessionIds());
    }

    /**
     * The account may hold any number of logins, and this runs inside a request
     * somebody is waiting on — under `single_session`, inside the callback
     * itself. Dropping the rows one at a time paid a round-trip apiece for work
     * one statement does, and where revocation is declined that was the whole
     * cost of the call.
     */
    public function test_the_rows_are_dropped_in_one_statement(): void
    {
        $user = TestUser::create(['uzair_id' => '7012']);
        $this->login($user, 'phone-session', 'phone_token');
        $this->login($user, 'desktop-session', 'desktop_token');
        $this->login($user, 'tablet-session', 'tablet_token');

        Socialite::shouldReceive('driver')->never();

        $deletes = 0;
        DB::listen(function (QueryExecuted $query) use (&$deletes): void {
            if (str_starts_with(strtolower(trim($query->sql)), 'delete from "oauth_tokens"')) {
                $deletes++;
            }
        });

        $ended = (new EndSessions)($user->id, revoke: false);

        $this->assertSame(3, $ended);
        $this->assertSame(1, $deletes);
        $this->assertSame(0, OauthToken::query()->count());
    }

    /**
     * An account holding nothing still has its stored sessions cleared: the
     * rows are what the middleware reads, but a session the store is still
     * serving is a device that never reaches it.
     */
    public function test_an_account_without_logins_still_loses_its_stored_sessions(): void
    {
        config(['session.driver' => 'database']);

        $user = TestUser::create(['uzair_id' => '7013']);

        DB::table('sessions')->insert([
            'id' => 'orphan-session',
            'user_id' => $user->id,
            'payload' => '',
            'last_activity' => now()->getTimestamp(),
        ]);

        Socialite::shouldReceive('driver')->never();

        $ended = (new EndSessions)($user->id);

        $this->assertSame(0, $ended);
        $this->assertSame([], $this->storedSessionIds());
    }

    private function login(TestUser $user, string $sessionId, string $accessToken): void
    {
        $user->tokens()->create([
            'access_token' => $accessToken,
            'session_id' => $sessionId,
        ]);

        DB::table('sessions')->insert([
            'id' => $sessionId,
            'user_id' => $user->id,
            'payload' => '',
            'last_activity' => now()->getTimestamp(),
        ]);
    }

    /**
     * @return array<int, string>
     */
    private function storedSessionIds(): array
    {
        return DB::table('sessions')
            ->orderBy('id')
            ->pluck('id')
            ->map(fn (mixed $id): string => is_string($id) ? $id : '')
            ->all();
    }
}
