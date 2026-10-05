<?php

namespace Uzairports\Uzairid\Tests;

use Illuminate\Http\Request;
use Laravel\Socialite\Two\User as SocialiteUser;
use Uzairports\Uzairid\Actions\RecordLogin;
use Uzairports\Uzairid\Models\OauthToken;

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
