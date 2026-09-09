<?php

namespace Uzairports\Uzairid\Tests;

use Exception;
use GuzzleHttp\Promise\PromiseInterface;
use Illuminate\Database\UniqueConstraintViolationException;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use Laravel\Socialite\Facades\Socialite;
use Laravel\Socialite\Two\Token;
use Mockery;
use Uzairports\Uzairid\Actions\EndSessions;
use Uzairports\Uzairid\Actions\RefreshAccessToken;
use Uzairports\Uzairid\Models\OauthToken;
use Uzairports\Uzairid\Socialite\UzairportsProvider;

class OauthTokenTest extends TestCase
{
    public function test_the_sweep_preserves_a_login_refreshed_after_its_chunk_was_read(): void
    {
        $user = TestUser::create(['uzair_id' => 'refreshed-during-sweep']);
        $token = $user->tokens()->create([
            'access_token' => 'old-access',
            'refresh_token' => 'old-refresh',
            'expires_at' => now()->subMinute(),
            'session_id' => 'active-session',
        ]);
        $token->forceFill(['updated_at' => now()->subMinutes(241)])->saveQuietly();

        $provider = Mockery::mock(UzairportsProvider::class);
        $provider->shouldReceive('refreshToken')->with('old-refresh')->once()->andReturn(new Token('new-access', 'new-refresh', 3600, []));
        $provider->shouldReceive('logoutAsync')->never();
        $provider->shouldReceive('revokeRefreshTokenAsync')->never();
        Socialite::shouldReceive('driver')->with('uzairports')->once()->andReturn($provider);

        $refreshed = false;
        OauthToken::retrieved(function (OauthToken $snapshot) use (&$refreshed, $token): void {
            if ($refreshed || $snapshot->id !== $token->id) {
                return;
            }

            $refreshed = true;
            $this->assertTrue((new RefreshAccessToken)(OauthToken::query()->findOrFail($token->id)));
        });

        try {
            $this->assertSame(0, (new OauthToken)->pruneAll());
        } finally {
            OauthToken::flushEventListeners();
        }

        $this->assertTrue($refreshed);
        $this->assertSame('new-refresh', OauthToken::query()->findOrFail($token->id)->refresh_token);
    }

    public function test_single_pruning_uses_current_grants_and_forgets_the_cached_login(): void
    {
        config(['uzairports.login_cache_ttl' => 60]);
        $user = TestUser::create(['uzair_id' => 'single-prune']);
        $token = $user->tokens()->create([
            'access_token' => 'old-access',
            'refresh_token' => 'old-refresh',
            'expires_at' => now()->addHour(),
            'session_id' => 'single-session',
        ]);
        $token->cacheLogin('single-session');
        OauthToken::query()->findOrFail($token->id)->forceFill([
            'access_token' => 'new-access',
            'refresh_token' => 'new-refresh',
        ])->save();

        $provider = Mockery::mock(UzairportsProvider::class);
        $provider->shouldReceive('logoutAsync')->with('new-access')->once()->andReturnUsing(function () use ($token): PromiseInterface {
            $this->assertSame(0, DB::transactionLevel());
            $this->assertModelMissing($token);
            $this->assertNull(OauthToken::cachedLogin('single-session'));

            return $this->revoked();
        });
        $provider->shouldReceive('revokeRefreshTokenAsync')->with('new-refresh')->once()->andReturn($this->revoked());
        Socialite::shouldReceive('driver')->with('uzairports')->once()->andReturn($provider);

        $this->assertTrue($token->prune());
        $this->assertFalse($token->prune());
    }

    public function test_a_vetoed_prune_keeps_the_login_and_does_not_revoke_its_grants(): void
    {
        $user = TestUser::create(['uzair_id' => 'vetoed-prune']);
        $token = $user->tokens()->create(['access_token' => 'access', 'refresh_token' => 'refresh']);
        $token->forceFill(['updated_at' => now()->subMinutes(241)])->saveQuietly();
        Socialite::shouldReceive('driver')->never();
        OauthToken::deleting(fn (): bool => false);

        try {
            $this->assertSame(0, (new OauthToken)->pruneAll());
            $this->assertFalse($token->prune());
        } finally {
            OauthToken::flushEventListeners();
        }

        $this->assertModelExists($token);
    }

    public function test_a_stale_snapshot_cannot_cache_a_login_after_it_was_ended(): void
    {
        config(['uzairports.login_cache_ttl' => 10]);

        $user = TestUser::create(['uzair_id' => 'cache-after-logout']);
        $token = $user->tokens()->create([
            'access_token' => 'access',
            'session_id' => 'ended-session',
            'expires_at' => now()->addHour(),
        ]);
        $snapshot = OauthToken::query()->findOrFail($token->id);
        $token->cacheLogin('ended-session');

        (new EndSessions)($user->id, revoke: false);
        $snapshot->cacheLogin('ended-session');

        $this->assertNull(OauthToken::cachedLogin('ended-session'));
        $this->assertModelMissing($snapshot);
    }

    public function test_caching_a_snapshot_uses_the_current_expiry_and_session(): void
    {
        config(['uzairports.login_cache_ttl' => 10]);

        $user = TestUser::create(['uzair_id' => 'cache-new-expiry']);
        $token = $user->tokens()->create([
            'access_token' => 'access',
            'session_id' => 'current-session',
            'expires_at' => now()->addHour(),
        ]);
        OauthToken::query()->findOrFail($token->id)->forceFill(['expires_at' => null])->save();

        $token->cacheLogin('current-session');
        $token->cacheLogin('unrelated-session');

        $this->assertSame(['user' => (string) $user->id, 'expires_at' => null], OauthToken::cachedLogin('current-session'));
        $this->assertNull(OauthToken::cachedLogin('unrelated-session'));
    }

    protected function tearDown(): void
    {
        Mockery::close();

        parent::tearDown();
    }

    public function test_tokens_are_encrypted_in_database(): void
    {
        $user = TestUser::create([
            'uzair_id' => '1001',
            'name' => 'John Doe',
            'email' => 'john@uzairports.com',
        ]);

        $token = $user->token()->create([
            'access_token' => 'plain_access_secret',
            'refresh_token' => 'plain_refresh_secret',
            'expires_at' => now()->addHour(),
        ]);

        $this->assertSame('plain_access_secret', $token->access_token);
        $this->assertSame('plain_refresh_secret', $token->refresh_token);

        // Fetch the raw attribute directly from PDO / DB
        $raw = DB::table('oauth_tokens')->where('id', $token->id)->first();

        $this->assertNotNull($raw);
        $this->assertNotSame('plain_access_secret', $raw->access_token);
        $this->assertNotSame('plain_refresh_secret', $raw->refresh_token);
    }

    public function test_the_readable_pair_hands_back_what_was_stored(): void
    {
        $user = TestUser::create(['uzair_id' => '1002']);

        $token = $user->token()->create([
            'access_token' => 'plain_access_secret',
            'refresh_token' => null,
        ]);

        $this->assertSame('plain_access_secret', $token->readableAccessToken());
        $this->assertNull($token->readableRefreshToken());
    }

    /**
     * A value written under a key the application no longer holds — a rotated
     * `APP_KEY` with no `APP_PREVIOUS_KEYS` behind it, a dump restored into
     * another environment — cannot be read back at all, and reaching for the
     * property raises where it stands.
     *
     * The readable pair answers null instead, so a login nobody can spend is
     * still a login the caller can end.
     */
    public function test_a_token_that_will_not_open_reads_as_nothing(): void
    {
        $user = TestUser::create(['uzair_id' => '1002b']);

        $token = $user->token()->create([
            'access_token' => 'plain_access_secret',
            'refresh_token' => 'plain_refresh_secret',
        ]);

        DB::table('oauth_tokens')->where('id', $token->id)->update([
            'access_token' => 'not-a-value-this-key-can-open',
            'refresh_token' => 'not-a-value-this-key-can-open',
        ]);

        $stored = $token->fresh();

        $this->assertNotNull($stored);
        $this->assertNull($stored->readableAccessToken());
        $this->assertNull($stored->readableRefreshToken());
    }

    public function test_a_user_may_hold_one_login_per_device(): void
    {
        $user = TestUser::create(['uzair_id' => '1003']);

        $user->tokens()->create(['access_token' => 'phone', 'session_id' => 'phone-session']);
        $user->tokens()->create(['access_token' => 'desktop', 'session_id' => 'desktop-session']);

        $this->assertSame(2, $user->tokens()->count());
    }

    /**
     * A session reads its own login, so a second row for the same one would be
     * authoritative for whichever caller happened to find it first.
     */
    public function test_a_device_cannot_end_up_with_two_logins(): void
    {
        $user = TestUser::create(['uzair_id' => '1004']);

        $user->tokens()->create(['access_token' => 'first', 'session_id' => 'one-session']);

        $this->expectException(UniqueConstraintViolationException::class);

        $user->tokens()->create(['access_token' => 'second', 'session_id' => 'one-session']);
    }

    public function test_has_expired_and_expires_within(): void
    {
        $user = TestUser::create(['uzair_id' => '1002']);

        $token = $user->token()->create([
            'access_token' => 'test',
            'expires_at' => now()->addSeconds(30),
        ]);

        $this->assertFalse($token->hasExpired());
        $this->assertTrue($token->expiresWithin(60));
        $this->assertFalse($token->expiresWithin(10));
    }

    /**
     * The row is written on refresh and on nothing else, so an access token
     * that outlives the pruning window would leave the login untouched while
     * its owner was still working — and pruned out from under them.
     */
    public function test_a_login_still_in_use_survives_pruning(): void
    {
        config(['session.lifetime' => 120]);

        $user = TestUser::create(['uzair_id' => '1005']);

        $token = $user->tokens()->create([
            'access_token' => 'a_token_that_outlives_the_window',
            'expires_at' => now()->addHours(8),
            'session_id' => 'desktop-session',
        ]);

        $this->travel(5)->hours();

        $token->keepAlive();

        $this->assertSame(0, (new OauthToken)->prunable()->count());
    }

    public function test_a_login_nothing_has_touched_is_pruned(): void
    {
        config(['session.lifetime' => 120]);

        $user = TestUser::create(['uzair_id' => '1006']);

        $user->tokens()->create([
            'access_token' => 'left_behind_by_a_closed_browser',
            'session_id' => 'abandoned-session',
        ]);

        $this->travel(5)->hours();

        $this->assertSame(1, (new OauthToken)->prunable()->count());
    }

    /**
     * `timestamps()` leaves the column nullable, so a row written around
     * Eloquent — a seeder, a data migration, an import — can arrive with no
     * write date. Null answers no comparison, so `updated_at < ?` on its own
     * kept such a row for good: nothing else would ever date it.
     */
    public function test_a_login_with_no_write_date_is_pruned(): void
    {
        config(['session.lifetime' => 120]);

        $user = TestUser::create(['uzair_id' => '1013']);

        DB::table('oauth_tokens')->insert([
            'user_id' => $user->getKey(),
            'session_id' => 'imported-session',
            'access_token' => 'written_around_eloquent',
            'created_at' => null,
            'updated_at' => null,
        ]);

        $this->assertSame(1, (new OauthToken)->prunable()->count());
    }

    /**
     * A closed browser never signs out, so the grant it was issued outlives
     * the row unless the sweep hands it back.
     */
    public function test_pruning_a_login_gives_its_grant_up_at_the_identity_provider(): void
    {
        config(['session.lifetime' => 120]);

        $user = TestUser::create(['uzair_id' => '1011']);

        $user->tokens()->create([
            'access_token' => 'abandoned_access_token',
            'refresh_token' => 'abandoned_refresh_token',
            'session_id' => 'abandoned-session',
        ]);

        $provider = Mockery::mock(UzairportsProvider::class);
        $provider->shouldReceive('logoutAsync')->with('abandoned_access_token')->once()->andReturn($this->revoked());
        $provider->shouldReceive('revokeRefreshTokenAsync')->with('abandoned_refresh_token')->once()->andReturn($this->revoked());

        Socialite::shouldReceive('driver')->with('uzairports')->andReturn($provider);

        $this->travel(5)->hours();

        $this->assertSame(0, Artisan::call('model:prune', ['--model' => [OauthToken::class]]));

        $this->assertSame(0, OauthToken::query()->count());
    }

    /**
     * The sweep runs over a whole table, so an installation whose grants expire
     * on their own may not want a revocation call per row.
     */
    public function test_the_sweep_can_be_told_not_to_revoke(): void
    {
        config(['session.lifetime' => 120, 'uzairports.revoke_on_prune' => false]);

        $user = TestUser::create(['uzair_id' => '1012']);

        $user->tokens()->create([
            'access_token' => 'abandoned_access_token',
            'session_id' => 'abandoned-session',
        ]);

        Socialite::shouldReceive('driver')->never();

        $this->travel(5)->hours();

        $this->assertSame(0, Artisan::call('model:prune', ['--model' => [OauthToken::class]]));

        $this->assertSame(0, OauthToken::query()->count());
    }

    /**
     * A revocation raised rather than logged would leave the row behind — and
     * the sweep would come back for it tomorrow, and every day the identity
     * provider stayed unreachable.
     */
    public function test_a_refused_revocation_still_lets_the_row_go(): void
    {
        config(['session.lifetime' => 120]);

        $user = TestUser::create(['uzair_id' => '1013']);

        $user->tokens()->create([
            'access_token' => 'abandoned_access_token',
            'session_id' => 'abandoned-session',
        ]);

        $provider = Mockery::mock(UzairportsProvider::class);
        $provider->shouldReceive('logoutAsync')->once()->andThrow(new Exception('SSO service unavailable'));

        Socialite::shouldReceive('driver')->with('uzairports')->andReturn($provider);

        $this->travel(5)->hours();

        $this->assertSame(0, Artisan::call('model:prune', ['--model' => [OauthToken::class]]));

        $this->assertSame(0, OauthToken::query()->count());
    }

    /**
     * Keeping the row alive costs one write per half a session lifetime, not
     * one per request.
     */
    public function test_keeping_a_login_alive_does_not_rewrite_a_recent_row(): void
    {
        config(['session.lifetime' => 120]);

        $user = TestUser::create(['uzair_id' => '1007']);

        $token = $user->tokens()->create([
            'access_token' => 'recently_written',
            'session_id' => 'desktop-session',
        ]);

        $writtenAt = $token->updated_at;

        $this->travel(10)->minutes();

        $token->keepAlive();

        $stored = $token->fresh();

        $this->assertNotNull($writtenAt);
        $this->assertNotNull($stored);
        $this->assertNotNull($stored->updated_at);
        $this->assertTrue($writtenAt->equalTo($stored->updated_at));
    }

    /**
     * A row written around Eloquent — a raw insert, an import from an earlier
     * version — carries no `updated_at`. Null answers no comparison, so such a
     * row would never be pruned either; stamping it as seen now both answers
     * the question and puts it back in reach of the sweep.
     */
    public function test_a_login_whose_row_was_never_stamped_is_stamped_as_seen_now(): void
    {
        config(['session.lifetime' => 120]);

        $user = TestUser::create(['uzair_id' => '1010']);

        $token = $user->tokens()->create([
            'access_token' => 'imported_without_timestamps',
            'session_id' => 'imported-session',
        ]);

        DB::table('oauth_tokens')->where('id', $token->getKey())->update(['updated_at' => null]);

        $token->refresh();

        $this->assertNull($token->updated_at);

        $token->keepAlive();

        $stored = $token->fresh();

        $this->assertNotNull($stored);
        $this->assertNotNull($stored->updated_at);
        $this->assertSame(0, (new OauthToken)->prunable()->count());
    }

    public function test_the_device_label_is_read_off_the_user_agent(): void
    {
        $user = TestUser::create(['uzair_id' => '1008']);

        $token = $user->tokens()->create([
            'access_token' => 'test',
            'session_id' => 'desktop-session',
            'user_agent' => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        ]);

        $this->assertSame('Chrome — Windows', $token->deviceLabel());

        // Chrome names itself Safari too, and Edge names itself both; the more
        // specific token has to win.
        $token->user_agent = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0';
        $this->assertSame('Edge — macOS', $token->deviceLabel());

        $token->user_agent = 'Mozilla/5.0 (Linux; Android 14; SAMSUNG SM-S928B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/24.0 Chrome/118.0.0.0 Mobile Safari/537.36';
        $this->assertSame('Samsung Internet — Android', $token->deviceLabel());

        // Nothing recognizable is handed back as it came, not guessed at.
        $token->user_agent = 'curl/8.4.0';
        $this->assertSame('curl/8.4.0', $token->deviceLabel());

        $token->user_agent = null;
        $this->assertSame('Unknown device', $token->deviceLabel());
    }

    public function test_uzbek_localization_is_supported(): void
    {
        app()->setLocale('uz');

        $this->assertSame('Noma’lum qurilma', __('uzairid::messages.unknown_device'));
        $this->assertSame('Kirish amalga oshmadi. Qaytadan urinib ko‘ring.', __('uzairid::messages.authentication_failed'));
        $this->assertSame('UzAirports ID sessiyasi muddati tugadi.', __('uzairid::messages.session_expired'));
        $this->assertSame('Ushbu qurilmadagi seans yakunlandi.', __('uzairid::messages.session_ended'));
        $this->assertSame('Kirish yakunlanmadi: sessiya saqlanib qolmadi. Bitta sahifada qaytadan kiring.', __('uzairid::messages.handshake_lost'));
    }
}
