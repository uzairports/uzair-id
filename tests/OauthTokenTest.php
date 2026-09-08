<?php

namespace Uzairports\Uzairid\Tests;

use Illuminate\Database\UniqueConstraintViolationException;
use Illuminate\Support\Facades\DB;
use Uzairports\Uzairid\Models\OauthToken;

class OauthTokenTest extends TestCase
{
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

        // Nothing recognisable is handed back as it came, not guessed at.
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
