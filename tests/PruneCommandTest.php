<?php

namespace Uzairports\Uzairid\Tests;

use Illuminate\Support\Facades\Artisan;
use Laravel\Socialite\Facades\Socialite;

class PruneCommandTest extends TestCase
{
    public function test_uzair_prune_command_deletes_expired_tokens(): void
    {
        $user = TestUser::create(['uzair_id' => '8001']);

        $abandoned = $user->tokens()->create([
            'access_token' => 'abandoned_token',
            'session_id' => 'expired-session',
        ]);

        $active = $user->tokens()->create([
            'access_token' => 'active_token',
            'session_id' => 'active-session',
        ]);

        $abandoned->forceFill(['updated_at' => now()->subMinutes(241)])->saveQuietly();

        $exitCode = Artisan::call('uzair:prune');

        $this->assertSame(0, $exitCode);
        $this->assertModelMissing($abandoned);
        $this->assertModelExists($active);
    }

    public function test_uzair_prune_command_supports_chunk_option(): void
    {
        $user = TestUser::create(['uzair_id' => '8002']);

        $abandoned = $user->tokens()->create([
            'access_token' => 'abandoned_token',
            'session_id' => 'expired-session',
        ]);

        $abandoned->forceFill(['updated_at' => now()->subMinutes(241)])->saveQuietly();

        $exitCode = Artisan::call('uzair:prune', ['--chunk' => 50]);

        $this->assertSame(0, $exitCode);
        $this->assertModelMissing($abandoned);
    }

    public function test_uzair_prune_command_supports_no_revoke_option(): void
    {
        config(['uzairports.revoke_on_prune' => true]);

        $user = TestUser::create(['uzair_id' => '8003']);

        $abandoned = $user->tokens()->create([
            'access_token' => 'abandoned_token',
            'session_id' => 'expired-session',
        ]);

        $abandoned->forceFill(['updated_at' => now()->subMinutes(241)])->saveQuietly();

        Socialite::shouldReceive('driver')->never();

        $exitCode = Artisan::call('uzair:prune', ['--no-revoke' => true]);

        $this->assertSame(0, $exitCode);
        $this->assertModelMissing($abandoned);
    }
}
