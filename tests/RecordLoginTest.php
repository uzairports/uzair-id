<?php

namespace Uzairports\Uzairid\Tests;

use Illuminate\Http\Request;
use Laravel\Socialite\Facades\Socialite;
use Laravel\Socialite\Two\User as SocialiteUser;
use Mockery;
use Uzairports\Uzairid\Actions\RecordLogin;
use Uzairports\Uzairid\Models\OauthToken;
use Uzairports\Uzairid\Socialite\UzairportsProvider;

class RecordLoginTest extends TestCase
{
    public function test_record_login_does_not_overwrite_mobile_login_when_session_is_null(): void
    {
        $user = TestUser::create(['uzair_id' => '6001', 'name' => 'Mobile User']);

        $mobileToken = (new OauthToken)->forceFill([
            'user_id' => $user->getKey(),
            'personal_access_token_id' => 999,
            'session_id' => null,
            'access_token' => 'mobile-access',
            'refresh_token' => 'mobile-refresh',
            'expires_at' => now()->addHour(),
        ]);
        $mobileToken->save();

        $request = Request::create('/');
        $socialiteUser = SocialiteUser::fake([
            'id' => '6001',
            'name' => 'Mobile User',
            'token' => 'sessionless-access',
            'refreshToken' => 'sessionless-refresh',
            'expiresIn' => 3600,
        ]);

        $recordLogin = app(RecordLogin::class);
        $recorded = $recordLogin($request, $socialiteUser, $user, null, null);

        $this->assertNotSame($mobileToken->getKey(), $recorded->getKey());
        $this->assertNull($recorded->personal_access_token_id);
        $this->assertSame(999, $mobileToken->fresh()?->personal_access_token_id);
        $this->assertSame(2, OauthToken::query()->where('user_id', $user->getKey())->count());
    }

    /**
     * Signing in again under the same session reuses the row. The grants it
     * held are overwritten, and nothing would ever surrender them after that.
     */
    public function test_signing_in_again_under_the_same_session_hands_back_the_grants_it_replaces(): void
    {
        $user = TestUser::create(['uzair_id' => '6003', 'name' => 'Returning User']);

        $user->tokens()->create([
            'access_token' => 'replaced-access',
            'refresh_token' => 'replaced-refresh',
            'session_id' => 'session-abc',
        ]);

        $provider = Mockery::mock(UzairportsProvider::class);
        $provider->shouldReceive('logoutAsync')->with('replaced-access')->once()->andReturn($this->revoked());
        $provider->shouldReceive('revokeRefreshTokenAsync')->with('replaced-refresh')->once()->andReturn($this->revoked());

        Socialite::shouldReceive('driver')->with('uzairports')->andReturn($provider);

        $socialiteUser = SocialiteUser::fake([
            'id' => '6003',
            'token' => 'new-access',
            'refreshToken' => 'new-refresh',
        ]);

        $recorded = app(RecordLogin::class)(Request::create('/'), $socialiteUser, $user, 'session-abc');

        $this->assertSame('new-access', $recorded->fresh()?->access_token);
        $this->assertSame(1, $user->tokens()->count());
    }

    public function test_record_login_truncates_long_ip_address(): void
    {
        $user = TestUser::create(['uzair_id' => '6002', 'name' => 'Long IP User']);

        $longIp = 'fe80::1ff:fe23:4567:890a%eth2-extra-long-interface-name-1234567890';
        $request = Request::create('/', server: ['REMOTE_ADDR' => $longIp]);

        $socialiteUser = SocialiteUser::fake([
            'id' => '6002',
            'name' => 'Long IP User',
            'token' => 'token',
            'refreshToken' => 'refresh',
            'expiresIn' => 3600,
        ]);

        $recordLogin = app(RecordLogin::class);
        $recorded = $recordLogin($request, $socialiteUser, $user, 'session-abc');

        $this->assertLessThanOrEqual(45, strlen((string) $recorded->ip_address));
    }
}
