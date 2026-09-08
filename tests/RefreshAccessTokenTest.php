<?php

namespace Uzairports\Uzairid\Tests;

use Exception;
use Illuminate\Support\Facades\Event;
use Laravel\Socialite\Facades\Socialite;
use Laravel\Socialite\Two\Token;
use Mockery;
use Uzairports\Uzairid\Actions\RefreshAccessToken;
use Uzairports\Uzairid\Events\UzairTokenRefreshed;
use Uzairports\Uzairid\Events\UzairTokenRefreshFailed;
use Uzairports\Uzairid\Socialite\UzairportsProvider;

class RefreshAccessTokenTest extends TestCase
{
    protected function tearDown(): void
    {
        Mockery::close();
        parent::tearDown();
    }

    public function test_successfully_refreshes_token_and_dispatches_event(): void
    {
        Event::fake([UzairTokenRefreshed::class]);

        $user = TestUser::create(['uzair_id' => '3001']);
        $token = $user->token()->create([
            'access_token' => 'old_access',
            'refresh_token' => 'old_refresh',
            'expires_at' => now()->subMinute(),
        ]);

        $provider = Mockery::mock(UzairportsProvider::class);
        $provider->shouldReceive('refreshToken')
            ->with('old_refresh')
            ->once()
            ->andReturn(new Token('new_access', 'new_refresh', 3600, []));

        Socialite::shouldReceive('driver')->with('uzairports')->andReturn($provider);

        $refresher = new RefreshAccessToken;
        $result = $refresher($token);

        $this->assertTrue($result);
        $this->assertSame('new_access', $token->fresh()->access_token);
        $this->assertSame('new_refresh', $token->fresh()->refresh_token);
        Event::assertDispatched(UzairTokenRefreshed::class);
    }

    public function test_dispatches_failed_event_when_remote_refresh_throws(): void
    {
        Event::fake([UzairTokenRefreshFailed::class]);

        $user = TestUser::create(['uzair_id' => '3002']);
        $token = $user->token()->create([
            'access_token' => 'old_access',
            'refresh_token' => 'faulty_refresh',
            'expires_at' => now()->subMinute(),
        ]);

        $provider = Mockery::mock(UzairportsProvider::class);
        $provider->shouldReceive('refreshToken')
            ->with('faulty_refresh')
            ->once()
            ->andThrow(new Exception('invalid_grant'));

        Socialite::shouldReceive('driver')->with('uzairports')->andReturn($provider);

        $refresher = new RefreshAccessToken;
        $result = $refresher($token);

        $this->assertFalse($result);
        Event::assertDispatched(UzairTokenRefreshFailed::class);
    }
}
