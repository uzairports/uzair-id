<?php

namespace Uzairports\Uzairid\Tests;

use Exception;
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

        $ended = (new EndSessions)($user->getKey());

        $this->assertSame(2, $ended);
        $this->assertSame(0, OauthToken::query()->count());
        $this->assertSame([], $this->storedSessionIds());
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

        $ended = (new EndSessions)($user->getKey(), 'desktop-session');

        $this->assertSame(1, $ended);
        $this->assertSame(['desktop-session'], OauthToken::query()->pluck('session_id')->all());
        $this->assertSame(['desktop-session'], $this->storedSessionIds());
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

        (new EndSessions)($user->getKey());

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

        (new EndSessions)($user->getKey());

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

        (new EndSessions)($user->getKey());

        $this->assertSame(0, OauthToken::query()->count());
        $this->assertSame(['phone-session'], $this->storedSessionIds());
    }

    private function login(TestUser $user, string $sessionId, string $accessToken): void
    {
        $user->tokens()->create([
            'access_token' => $accessToken,
            'session_id' => $sessionId,
        ]);

        DB::table('sessions')->insert([
            'id' => $sessionId,
            'user_id' => $user->getKey(),
            'payload' => '',
            'last_activity' => now()->getTimestamp(),
        ]);
    }

    /**
     * @return array<int, string>
     */
    private function storedSessionIds(): array
    {
        return DB::table('sessions')->orderBy('id')->pluck('id')->all();
    }
}
