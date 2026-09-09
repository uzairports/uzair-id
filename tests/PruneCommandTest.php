<?php

namespace Uzairports\Uzairid\Tests;

use Illuminate\Support\Facades\Artisan;

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
}
