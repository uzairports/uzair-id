<?php

namespace Uzairports\Uzairid\Tests;

use GuzzleHttp\Exception\RequestException;
use GuzzleHttp\Psr7\Request;
use GuzzleHttp\Psr7\Response;
use Illuminate\Contracts\Cache\Lock;
use Illuminate\Contracts\Cache\LockProvider;
use Illuminate\Contracts\Cache\LockTimeoutException;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Laravel\Socialite\Facades\Socialite;
use Laravel\Socialite\Two\Token;
use Mockery;
use Symfony\Component\HttpKernel\Exception\ServiceUnavailableHttpException;
use Uzairports\Uzairid\Actions\RefreshAccessToken;
use Uzairports\Uzairid\Events\UzairTokenRefreshed;
use Uzairports\Uzairid\Events\UzairTokenRefreshFailed;
use Uzairports\Uzairid\Models\OauthToken;
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

        $stored = $token->fresh();

        $this->assertTrue($result);
        $this->assertNotNull($stored);
        $this->assertSame('new_access', $stored->access_token);
        $this->assertSame('new_refresh', $stored->refresh_token);
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
            ->andThrow(new RequestException('Rejected grant', new Request('POST', 'https://sso.test/oauth/token'), new Response(400, [], '{"error":"invalid_grant"}')));

        Socialite::shouldReceive('driver')->with('uzairports')->andReturn($provider);

        $refresher = new RefreshAccessToken;
        $result = $refresher($token);

        $this->assertFalse($result);
        Event::assertDispatched(UzairTokenRefreshFailed::class);
    }

    public function test_a_token_another_process_already_renewed_is_adopted_instead_of_spent_again(): void
    {
        $token = $this->expiredToken('3003');

        $this->winnerStores($token, 'winner_access', 'winner_refresh');

        Socialite::shouldReceive('driver')->never();

        $result = (new RefreshAccessToken)($token);

        $this->assertTrue($result);
        $this->assertSame('winner_access', $token->access_token);
        $this->assertSame('winner_refresh', $token->refresh_token);
    }

    public function test_a_request_that_waits_out_the_lock_adopts_what_the_winner_stored(): void
    {
        $token = $this->expiredToken('3004');

        $this->winnerStores($token, 'winner_access', 'winner_refresh');
        $this->lockTimesOut();

        Socialite::shouldReceive('driver')->never();

        $result = (new RefreshAccessToken)($token);

        $this->assertTrue($result);
        $this->assertSame('winner_access', $token->access_token);
    }

    public function test_a_request_that_waits_out_the_lock_is_refused_when_the_login_is_gone(): void
    {
        $token = $this->expiredToken('3005');

        OauthToken::query()->whereKey($token->getKey())->delete();
        $this->lockTimesOut();

        Socialite::shouldReceive('driver')->never();

        $this->assertFalse((new RefreshAccessToken)($token));
    }

    public function test_a_login_without_a_refresh_token_is_refused_without_asking_the_provider(): void
    {
        Event::fake([UzairTokenRefreshFailed::class]);

        $token = $this->expiredToken('3006', refreshToken: null);

        Socialite::shouldReceive('driver')->never();

        $this->assertFalse((new RefreshAccessToken)($token));
        Event::assertDispatched(UzairTokenRefreshFailed::class);
    }

    public function test_lock_contention_preserves_an_existing_login(): void
    {
        $token = $this->expiredToken('lock-contention');
        $this->lockTimesOut();
        Socialite::shouldReceive('driver')->never();

        try {
            (new RefreshAccessToken)($token);
            $this->fail('An in-progress refresh must answer with a temporary failure.');
        } catch (ServiceUnavailableHttpException $exception) {
            $this->assertSame(503, $exception->getStatusCode());
        }

        $this->assertModelExists($token);
        $this->assertSame('old_refresh', $token->refresh_token);
    }

    public function test_a_deleted_login_is_not_exchanged_after_acquiring_the_lock(): void
    {
        $token = $this->expiredToken('deleted-login');
        OauthToken::query()->whereKey($token->getKey())->delete();
        Socialite::shouldReceive('driver')->never();

        $this->assertFalse((new RefreshAccessToken)($token));
    }

    public function test_an_exchange_that_answers_with_an_empty_access_token_is_refused(): void
    {
        Event::fake([UzairTokenRefreshFailed::class]);

        $token = $this->expiredToken('3007');

        $this->providerReturns('old_refresh', new Token('', 'new_refresh', 3600, []));

        try {
            (new RefreshAccessToken)($token);
            $this->fail('An invalid token response must answer with a temporary failure.');
        } catch (ServiceUnavailableHttpException $exception) {
            $this->assertSame(503, $exception->getStatusCode());
        }

        $stored = $token->fresh();

        $this->assertNotNull($stored);
        $this->assertSame('old_access', $stored->access_token);
        $this->assertSame('old_refresh', $stored->refresh_token);
        Event::assertDispatched(UzairTokenRefreshFailed::class);
    }

    /**
     * An identity provider is not obliged to rotate the refresh token, and one
     * that answers with an empty `refresh_token` is saying it kept the grant as
     * it stands — not that the login has none. Overwriting the stored one with
     * nothing would leave the login unable to renew itself ever again.
     */
    public function test_a_provider_that_does_not_rotate_the_refresh_token_keeps_the_stored_one(): void
    {
        $token = $this->expiredToken('3008');

        $this->providerReturns('old_refresh', new Token('new_access', '', 3600, []));

        $this->assertTrue((new RefreshAccessToken)($token));

        $stored = $token->fresh();

        $this->assertNotNull($stored);
        $this->assertSame('new_access', $stored->access_token);
        $this->assertSame('old_refresh', $stored->refresh_token);
    }

    public function test_the_lock_is_taken_from_the_configured_store(): void
    {
        config()->set('uzairports.lock_store', 'shared');

        $token = $this->expiredToken('3010');

        $this->winnerStores($token, 'winner_access', 'winner_refresh');

        $lock = Mockery::mock(Lock::class);
        $lock->shouldReceive('block')->once()->andThrow(new LockTimeoutException);

        $store = Mockery::mock(LockProvider::class);
        $store->shouldReceive('lock')->once()->andReturn($lock);

        Cache::shouldReceive('store')->once()->with('shared')->andReturn($store);

        $this->assertTrue((new RefreshAccessToken)($token));
    }

    /**
     * The lock has to outlive the exchange it guards. One that expired at the
     * moment the request behind it stopped waiting would be released under its
     * holder, and both of them would then spend the same rotating refresh
     * token — the one collision the lock exists to prevent.
     */
    public function test_the_lock_outlives_the_wait_of_the_request_behind_it(): void
    {
        $token = $this->expiredToken('3012');

        $ttl = 0;
        $wait = 0;

        $lock = Mockery::mock(Lock::class);
        $lock->shouldReceive('block')->once()->andReturnUsing(
            function (int $seconds, callable $callback) use (&$wait): bool {
                $wait = $seconds;

                return (bool) $callback();
            }
        );

        $store = Mockery::mock(LockProvider::class);
        $store->shouldReceive('lock')->once()->andReturnUsing(
            function (string $name, int $seconds) use ($lock, &$ttl) {
                $ttl = $seconds;

                return $lock;
            }
        );

        Cache::shouldReceive('store')->once()->andReturn($store);

        $this->providerReturns('old_refresh', new Token('new_access', 'new_refresh', 3600, []));

        $this->assertTrue((new RefreshAccessToken)($token));

        $this->assertGreaterThan(
            UzairportsProvider::requestTimeout(),
            $wait,
            'A request must wait out an exchange running to the provider timeout.',
        );

        $this->assertGreaterThan(
            $wait,
            $ttl,
            'The lock must outlive the wait of the request behind it, or it is released under its holder.',
        );
    }

    /**
     * A grant written under a key the application no longer holds cannot be
     * exchanged for anything. Reaching for it used to raise the decryption
     * failure from here — a 500 on every request the login touched, including
     * the ones that would have ended it — where the login is simply refused and
     * its owner sent back through SSO.
     */
    public function test_a_refresh_token_that_will_not_open_is_refused_rather_than_raised(): void
    {
        Event::fake([UzairTokenRefreshFailed::class]);

        $token = $this->expiredToken('3013');

        DB::table('oauth_tokens')->where('id', $token->getKey())->update([
            'refresh_token' => 'not-a-value-this-key-can-open',
        ]);

        Socialite::shouldReceive('driver')->never();

        $this->assertFalse((new RefreshAccessToken)($token));
        Event::assertDispatched(UzairTokenRefreshFailed::class);
    }

    public function test_refreshed_token_without_expiry_adopts_default_token_ttl(): void
    {
        config()->set('uzairports.default_token_ttl', 7200);

        $token = $this->expiredToken('3011');

        $this->providerReturns('old_refresh', new Token('new_access', 'new_refresh', 0, []));

        $this->assertTrue((new RefreshAccessToken)($token));

        $stored = $token->fresh();
        $this->assertNotNull($stored);
        $this->assertSame('new_access', $stored->access_token);
        $this->assertNotNull($stored->expires_at);
        $this->assertEqualsWithDelta(7200, now()->diffInSeconds($stored->expires_at), 5);
    }

    private function expiredToken(string $uzairId, ?string $refreshToken = 'old_refresh'): OauthToken
    {
        $user = TestUser::create(['uzair_id' => $uzairId]);

        return $user->token()->create([
            'access_token' => 'old_access',
            'refresh_token' => $refreshToken,
            'expires_at' => now()->subMinute(),
        ]);
    }

    /**
     * Write the row the way the process that won the lock would have left it,
     * without touching the instance the caller is holding.
     */
    private function winnerStores(OauthToken $token, string $accessToken, string $refreshToken): void
    {
        $winner = OauthToken::query()->whereKey($token->getKey())->firstOrFail();

        $winner->forceFill([
            'access_token' => $accessToken,
            'refresh_token' => $refreshToken,
            'expires_at' => now()->addHour(),
        ])->save();
    }

    /**
     * Answer the exchange with the given token, once, for the expected grant.
     */
    private function providerReturns(string $expectedRefreshToken, Token $token): void
    {
        $provider = Mockery::mock(UzairportsProvider::class);
        $provider->shouldReceive('refreshToken')
            ->with($expectedRefreshToken)
            ->once()
            ->andReturn($token);

        Socialite::shouldReceive('driver')->with('uzairports')->andReturn($provider);
    }

    /**
     * Hand out a lock that is already held, so the caller waits it out.
     */
    private function lockTimesOut(): void
    {
        $lock = Mockery::mock(Lock::class);
        $lock->shouldReceive('block')->once()->andThrow(new LockTimeoutException);

        $store = Mockery::mock(LockProvider::class);
        $store->shouldReceive('lock')->once()->andReturn($lock);

        Cache::shouldReceive('store')->once()->andReturn($store);
    }
}
