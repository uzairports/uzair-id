<?php

namespace Uzairports\Uzairid\Tests;

use Illuminate\Support\Facades\Artisan;
use Laravel\Socialite\Facades\Socialite;
use Mockery;
use RuntimeException;
use Uzairports\Uzairid\Models\OauthToken;
use Uzairports\Uzairid\Socialite\UzairportsProvider;

class PruneCommandTest extends TestCase
{
    protected function tearDown(): void
    {
        OauthToken::flushPruner();

        Mockery::close();

        parent::tearDown();
    }

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

    /**
     * A chunk's grants go back to the identity provider together.
     *
     * The sweep used to surrender one row at a time and wait out each of them
     * before reading the next, so a backlog of thousands cost a revocation
     * timeout apiece and took as long as the sum of them all. Resolving the
     * driver once for the whole chunk is what says they went out as a batch:
     * a sweep paying per row asks for it again on every one.
     */
    public function test_a_chunk_of_grants_is_surrendered_in_one_batch(): void
    {
        config(['uzairports.revoke_on_prune' => true]);

        $user = TestUser::create(['uzair_id' => '8004']);

        $provider = Mockery::mock(UzairportsProvider::class);

        foreach (['first', 'second', 'third'] as $device) {
            $abandoned = $user->tokens()->create([
                'access_token' => $device.'_token',
                'session_id' => $device.'-session',
            ]);

            $abandoned->forceFill(['updated_at' => now()->subMinutes(241)])->saveQuietly();

            $provider->shouldReceive('logoutAsync')
                ->with($device.'_token')
                ->once()
                ->andReturn($this->revoked());
        }

        Socialite::shouldReceive('driver')->with('uzairports')->once()->andReturn($provider);

        $exitCode = Artisan::call('uzair:prune');

        $this->assertSame(0, $exitCode);
        $this->assertSame(0, OauthToken::query()->count());
    }

    /**
     * A login the sweep orphans stops answering for the row it no longer has.
     *
     * `login_cache_ttl` lets a resolved login stand in for reading the row, and
     * the sweep is the one path that used to leave those entries behind — the
     * device would keep being let through until the entry lapsed. The sweep is
     * holding every session id it is about to orphan anyway.
     */
    public function test_the_sweep_forgets_the_logins_it_orphans(): void
    {
        config([
            'uzairports.login_cache_ttl' => 60,
            'uzairports.revoke_on_prune' => false,
        ]);

        $user = TestUser::create(['uzair_id' => '8005']);

        $abandoned = $user->tokens()->create([
            'access_token' => 'abandoned_token',
            'session_id' => 'expired-session',
            'expires_at' => now()->addHour(),
        ]);

        $abandoned->cacheLogin('expired-session');

        $this->assertNotNull(OauthToken::cachedLogin('expired-session'));

        $abandoned->forceFill(['updated_at' => now()->subMinutes(241)])->saveQuietly();

        Artisan::call('uzair:prune');

        $this->assertModelMissing($abandoned);
        $this->assertNull(OauthToken::cachedLogin('expired-session'));
    }

    /**
     * A row the sweep cannot drop does not leave the rest of the backlog
     * standing, which is what the trait's own sweep promises.
     */
    public function test_the_sweep_reports_a_row_it_cannot_drop_and_carries_on(): void
    {
        config(['uzairports.revoke_on_prune' => false]);

        $user = TestUser::create(['uzair_id' => '8006']);

        $first = $user->tokens()->create([
            'access_token' => 'first_token',
            'session_id' => 'first-session',
        ]);

        $second = $user->tokens()->create([
            'access_token' => 'second_token',
            'session_id' => 'second-session',
        ]);

        foreach ([$first, $second] as $token) {
            $token->forceFill(['updated_at' => now()->subMinutes(241)])->saveQuietly();
        }

        OauthToken::deleting(function (OauthToken $token): void {
            if ($token->session_id === 'first-session') {
                throw new RuntimeException('this row will not go');
            }
        });

        try {
            $exitCode = Artisan::call('uzair:prune');
        } finally {
            OauthToken::flushEventListeners();
        }

        $this->assertSame(0, $exitCode);
        $this->assertModelExists($first);
        $this->assertModelMissing($second);
    }
}
