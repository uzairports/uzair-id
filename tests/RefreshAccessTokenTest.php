<?php

namespace Uzairports\Uzairid\Tests;

use GuzzleHttp\Exception\ConnectException;
use GuzzleHttp\Exception\RequestException;
use GuzzleHttp\Promise\PromiseInterface;
use GuzzleHttp\Psr7\Request;
use GuzzleHttp\Psr7\Response;
use Illuminate\Contracts\Cache\Lock;
use Illuminate\Contracts\Cache\LockProvider;
use Illuminate\Contracts\Cache\LockTimeoutException;
use Illuminate\Contracts\Cache\Repository as CacheRepository;
use Illuminate\Database\QueryException;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Log;
use Laravel\Socialite\Facades\Socialite;
use Laravel\Socialite\Two\Token;
use Mockery;
use stdClass;
use Symfony\Component\HttpKernel\Exception\ServiceUnavailableHttpException;
use Uzairports\Uzairid\Actions\EndSessions;
use Uzairports\Uzairid\Actions\RefreshAccessToken;
use Uzairports\Uzairid\Events\UzairTokenRefreshed;
use Uzairports\Uzairid\Events\UzairTokenRefreshFailed;
use Uzairports\Uzairid\Models\OauthToken;
use Uzairports\Uzairid\Socialite\UzairportsProvider;

class RefreshAccessTokenTest extends TestCase
{
    public function test_a_refresh_finishing_after_pruning_surrenders_its_new_grants(): void
    {
        $token = $this->expiredToken('pruned-during-refresh');
        $token->forceFill(['updated_at' => now()->subMinutes(241)])->saveQuietly();

        $provider = Mockery::mock(UzairportsProvider::class);
        $provider->shouldReceive('refreshToken')->with('old_refresh')->once()->andReturnUsing(function (): Token {
            $this->assertSame(1, (new OauthToken)->pruneAll());

            return new Token('new_access', 'new_refresh', 3600, []);
        });

        foreach (['old_access', 'new_access'] as $accessToken) {
            $provider->shouldReceive('logoutAsync')->with($accessToken)->once()->andReturnUsing(function () use ($token): PromiseInterface {
                $this->assertSame(0, DB::transactionLevel());
                $this->assertModelMissing($token);

                return $this->revoked();
            });
        }

        foreach (['old_refresh', 'new_refresh'] as $refreshToken) {
            $provider->shouldReceive('revokeRefreshTokenAsync')->with($refreshToken)->once()->andReturn($this->revoked());
        }

        Socialite::shouldReceive('driver')->with('uzairports')->andReturn($provider);

        $this->assertFalse((new RefreshAccessToken)($token));
        $this->assertModelMissing($token);
    }

    public function test_a_database_failure_after_refresh_surrenders_the_new_grants(): void
    {
        $token = $this->expiredToken('failed-refresh-write');
        Event::fake([UzairTokenRefreshed::class, UzairTokenRefreshFailed::class]);
        $original = $token->getRawOriginal();

        $provider = Mockery::mock(UzairportsProvider::class);
        $provider->shouldReceive('refreshToken')->once()->andReturn(new Token('new-access', 'new-refresh', 3600, []));
        $provider->shouldReceive('logoutAsync')->with('new-access')->once()->andReturnUsing(function (): PromiseInterface {
            $this->assertSame(0, DB::transactionLevel());

            return $this->revoked();
        });
        $provider->shouldReceive('revokeRefreshTokenAsync')->with('new-refresh')->once()->andReturn($this->revoked());
        Socialite::shouldReceive('driver')->with('uzairports')->andReturn($provider);

        OauthToken::updating(function (): void {
            DB::statement('update missing_refresh_test_table set id = 1');
        });

        try {
            (new RefreshAccessToken)($token);
            $this->fail('The database failure must remain visible to the caller.');
        } catch (QueryException $exception) {
            Event::assertDispatched(UzairTokenRefreshFailed::class, fn (UzairTokenRefreshFailed $event): bool => $event->exception === $exception);
        } finally {
            OauthToken::flushEventListeners();
        }

        $stored = OauthToken::query()->findOrFail($token->id);
        $this->assertSame($original['access_token'], $stored->getRawOriginal('access_token'));
        $this->assertSame($original['refresh_token'], $stored->getRawOriginal('refresh_token'));
        Event::assertNotDispatched(UzairTokenRefreshed::class);
    }

    public function test_a_refresh_finishing_after_logout_surrenders_the_new_grants(): void
    {
        $user = TestUser::create(['uzair_id' => 'refresh-during-logout']);
        $token = $user->tokens()->create([
            'access_token' => 'old_access',
            'refresh_token' => 'old_refresh',
            'expires_at' => now()->subMinute(),
            'session_id' => 'ending-session',
        ]);

        Event::fake([UzairTokenRefreshed::class, UzairTokenRefreshFailed::class]);

        $provider = Mockery::mock(UzairportsProvider::class);
        $provider->shouldReceive('refreshToken')->with('old_refresh')->once()->andReturnUsing(function () use ($token): Token {
            $this->assertSame(0, DB::transactionLevel());
            (new EndSessions)->end(OauthToken::query()->findOrFail($token->id));

            return new Token('new_access', 'new_refresh', 3600, []);
        });

        foreach (['old_access', 'new_access'] as $accessToken) {
            $provider->shouldReceive('logoutAsync')->with($accessToken)->once()->andReturnUsing(function (): PromiseInterface {
                $this->assertSame(0, DB::transactionLevel());

                return $this->revoked();
            });
        }

        foreach (['old_refresh', 'new_refresh'] as $refreshToken) {
            $provider->shouldReceive('revokeRefreshTokenAsync')->with($refreshToken)->once()->andReturn($this->revoked());
        }

        Socialite::shouldReceive('driver')->with('uzairports')->andReturn($provider);

        $this->assertFalse((new RefreshAccessToken)($token));
        $this->assertModelMissing($token);
        Event::assertNotDispatched(UzairTokenRefreshed::class);
        Event::assertDispatched(UzairTokenRefreshFailed::class);
    }

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

    public function test_dispatches_failed_event_when_remote_refresh_returns_401(): void
    {
        Event::fake([UzairTokenRefreshFailed::class]);

        $user = TestUser::create(['uzair_id' => '30021']);
        $token = $user->token()->create([
            'access_token' => 'old_access',
            'refresh_token' => 'expired_refresh',
            'expires_at' => now()->subMinute(),
        ]);

        $provider = Mockery::mock(UzairportsProvider::class);
        $provider->shouldReceive('refreshToken')
            ->with('expired_refresh')
            ->once()
            ->andThrow(new RequestException('Unauthorized', new Request('POST', 'https://sso.test/oauth/token'), new Response(401, [], '{"error":"invalid_token"}')));

        Socialite::shouldReceive('driver')->with('uzairports')->andReturn($provider);

        $refresher = new RefreshAccessToken;
        $result = $refresher($token);

        $this->assertFalse($result);
        Event::assertDispatched(UzairTokenRefreshFailed::class);
    }

    /**
     * Credentials the identity provider will not authenticate say nothing about
     * the login that was presented with them. Read as a refused grant, one
     * mistyped `client_secret` signed every account out as its token came due.
     */
    public function test_credentials_the_provider_refuses_do_not_end_the_login(): void
    {
        $this->assertTheApplicationIsRefusedWithoutEndingTheLogin('invalid_client', 401);
    }

    /**
     * The other half of RFC 6749 §5.2's client-side pair: a client that is not
     * allowed this grant type at all. It arrives as a 400, which is also how a
     * refused grant arrives — the code is the only thing telling them apart.
     */
    public function test_a_client_refused_this_grant_type_does_not_end_the_login(): void
    {
        $this->assertTheApplicationIsRefusedWithoutEndingTheLogin('unauthorized_client', 400);
    }

    /**
     * Assert an application-level refusal is answered as unavailable: the row
     * stands, its grants are not handed back, and the identity provider is
     * still called on the next renewal — it answered, so there is no outage to
     * wait out, and pausing the calls would only postpone the log line.
     */
    private function assertTheApplicationIsRefusedWithoutEndingTheLogin(string $error, int $status): void
    {
        $this->tripOnTheFirstFailure();

        Event::fake([UzairTokenRefreshFailed::class]);

        $token = $this->expiredToken("client-{$error}", 'a_perfectly_good_refresh');

        $provider = Mockery::mock(UzairportsProvider::class);
        $provider->shouldReceive('refreshToken')
            ->with('a_perfectly_good_refresh')
            ->twice()
            ->andThrow(new RequestException(
                'Refused',
                new Request('POST', 'https://sso.test/oauth/token'),
                new Response($status, [], sprintf('{"error":"%s"}', $error)),
            ));

        $provider->shouldNotReceive('logoutAsync');
        $provider->shouldNotReceive('revokeRefreshTokenAsync');

        Socialite::shouldReceive('driver')->with('uzairports')->andReturn($provider);

        $this->assertUnavailable(fn (): bool => (new RefreshAccessToken)($token));
        $this->assertUnavailable(fn (): bool => (new RefreshAccessToken)($token));

        $stored = $token->fresh();

        $this->assertNotNull($stored);
        $this->assertSame('old_access', $stored->access_token);
        $this->assertSame('a_perfectly_good_refresh', $stored->refresh_token);
        Event::assertDispatched(UzairTokenRefreshFailed::class);
    }

    /**
     * A refusal has to say which refusal it was.
     *
     * The status alone does not: a grant the identity provider no longer
     * honors and a request it could not read both arrive as a 400, and the
     * remedies are opposite — the first means the login has to be made again,
     * the second is a misconfiguration. The log used to carry only the status,
     * so neither could be told from it.
     */
    public function test_the_refusal_records_the_oauth_error_code(): void
    {
        $token = $this->expiredToken('3015');

        $provider = Mockery::mock(UzairportsProvider::class);
        $provider->shouldReceive('refreshToken')
            ->once()
            ->andThrow(new RequestException(
                'Rejected grant',
                new Request('POST', 'https://sso.test/oauth/token'),
                new Response(400, [], '{"error":"invalid_grant","error_description":"The refresh token is invalid."}'),
            ));

        Socialite::shouldReceive('driver')->with('uzairports')->andReturn($provider);

        Log::shouldReceive('warning')
            ->once()
            ->withArgs(fn (string $message, array $context): bool => $context['http_status'] === 400
                && $context['oauth_error'] === 'invalid_grant'
                // The description is prose the provider writes and may repeat
                // the request back, so it stays out of the log.
                && ! array_key_exists('error_description', $context));

        $this->assertFalse((new RefreshAccessToken)($token));
    }

    /**
     * A refusal carrying no readable body is still a refusal, and must not
     * invent a code it was never given.
     */
    public function test_a_refusal_without_a_body_records_no_oauth_error(): void
    {
        $token = $this->expiredToken('3016');

        $provider = Mockery::mock(UzairportsProvider::class);
        $provider->shouldReceive('refreshToken')
            ->once()
            ->andThrow(new RequestException(
                'Bad gateway',
                new Request('POST', 'https://sso.test/oauth/token'),
                new Response(401, [], '<html>the proxy in front of it</html>'),
            ));

        Socialite::shouldReceive('driver')->with('uzairports')->andReturn($provider);

        Log::shouldReceive('warning')
            ->once()
            ->withArgs(fn (string $message, array $context): bool => $context['oauth_error'] === null);

        $this->assertFalse((new RefreshAccessToken)($token));
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
     * A store offering no atomic locks used to answer the request with a fatal
     * error rather than a lock, so a cache setting signed the user out. The
     * exchange it was guarding still has to happen — and the reason it went
     * unguarded has to be somewhere an operator can find it.
     */
    public function test_a_store_that_offers_no_lock_still_renews_the_token_and_says_so(): void
    {
        RefreshAccessToken::flushLockStoreWarnings();

        Log::shouldReceive('warning')->once()->with(Mockery::pattern('/offers no atomic locks/'));

        Cache::shouldReceive('store')->once()->andReturn(Mockery::mock(CacheRepository::class));

        $token = $this->expiredToken('3013');

        $this->providerReturns('old_refresh', new Token('new_access', 'new_refresh', 3600, []));

        $this->assertTrue((new RefreshAccessToken)($token));

        $stored = $token->fresh();

        $this->assertNotNull($stored);
        $this->assertSame('new_access', $stored->access_token);
    }

    /**
     * A lock nobody else can see is not a lock.
     *
     * `lock_store` is null by default, so whatever the application caches in is
     * what guards the one thing that may only be spent once. A store held in
     * the memory of a single process guards nothing between the processes
     * serving the application, and said nothing about it — the renewal simply
     * looked guarded. It is said once, not on every renewal that finds it.
     */
    public function test_a_lock_store_held_in_one_process_is_reported_once(): void
    {
        RefreshAccessToken::flushLockStoreWarnings();

        config(['cache.default' => 'array']);

        Log::shouldReceive('warning')->once()->with(Mockery::pattern('/memory of one process/'));

        $token = $this->expiredToken('3014');

        $this->providerReturns('old_refresh', new Token('new_access', 'new_refresh', 3600, []));

        $refresher = new RefreshAccessToken;

        $this->assertTrue($refresher($token));
        $this->assertTrue($refresher($token));
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

    /**
     * An identity provider that stopped answering is not asked again at once.
     *
     * Every renewal is its own lock and its own exchange, so nothing queues:
     * each request holding an expiring token paid the full request timeout on
     * its own before being told to come back, and those waits are held in
     * workers. There are far fewer workers than requests during a wave of
     * expiries, so an identity provider that was merely unreachable took the
     * whole application down with it.
     */
    public function test_a_provider_that_did_not_answer_is_left_alone_by_the_next_renewal(): void
    {
        $this->tripOnTheFirstFailure();

        $first = $this->expiredToken('cooldown-first');
        $second = $this->expiredToken('cooldown-second');

        $provider = Mockery::mock(UzairportsProvider::class);
        $provider->shouldReceive('refreshToken')->once()->andThrow($this->unreachable());

        Socialite::shouldReceive('driver')->with('uzairports')->andReturn($provider);

        $this->assertUnavailable(fn (): bool => (new RefreshAccessToken)($first));
        $this->assertUnavailable(fn (): bool => (new RefreshAccessToken)($second));

        // Neither login was ended over an outage that refused nothing.
        $this->assertModelExists($first);
        $this->assertModelExists($second);
    }

    /**
     * One failure is a hiccup, not an outage.
     *
     * A dropped connection, a rate limit, a response that arrived malformed —
     * these happen to healthy identity providers and cost one request one
     * timeout. Leaving the provider alone over each of them would stop the
     * application renewing logins for a cooldown every time one occurred.
     */
    public function test_a_single_failure_does_not_leave_the_provider_alone(): void
    {
        RefreshAccessToken::forgetProviderFailure();

        $first = $this->expiredToken('one-failure-first');
        $second = $this->expiredToken('one-failure-second');

        $provider = Mockery::mock(UzairportsProvider::class);
        $provider->shouldReceive('refreshToken')->once()->andThrow($this->unreachable());
        $provider->shouldReceive('refreshToken')->once()->andReturn(new Token('new_access', 'new_refresh', 3600, []));

        Socialite::shouldReceive('driver')->with('uzairports')->andReturn($provider);

        $this->assertUnavailable(fn (): bool => (new RefreshAccessToken)($first));
        $this->assertTrue((new RefreshAccessToken)($second));
    }

    /**
     * A success takes back what was counted, so blips never add up.
     */
    public function test_a_successful_exchange_forgets_the_failures_before_it(): void
    {
        RefreshAccessToken::forgetProviderFailure();
        config()->set('uzairports.provider_failure_threshold', 2);

        $first = $this->expiredToken('forgotten-failure-first');
        $second = $this->expiredToken('forgotten-failure-second');
        $third = $this->expiredToken('forgotten-failure-third');

        $provider = Mockery::mock(UzairportsProvider::class);
        $provider->shouldReceive('refreshToken')->once()->andThrow($this->unreachable());
        $provider->shouldReceive('refreshToken')->once()->andReturn(new Token('new_access', 'new_refresh', 3600, []));
        $provider->shouldReceive('refreshToken')->once()->andThrow($this->unreachable());

        Socialite::shouldReceive('driver')->with('uzairports')->andReturn($provider);

        $this->assertUnavailable(fn (): bool => (new RefreshAccessToken)($first));
        $this->assertTrue((new RefreshAccessToken)($second));

        // The failure before the success is forgotten, so this one is the
        // first of its window rather than the second.
        $this->assertUnavailable(fn (): bool => (new RefreshAccessToken)($third));
        $this->assertModelExists($third);
    }

    /**
     * A refusal is not an outage: the provider answered, and answered clearly.
     *
     * Recording it would leave every other login unable to reach the provider
     * because one of them was over.
     */
    public function test_a_refused_grant_does_not_leave_the_provider_alone(): void
    {
        RefreshAccessToken::forgetProviderFailure();

        $first = $this->expiredToken('refusal-first');
        $second = $this->expiredToken('refusal-second');

        $provider = Mockery::mock(UzairportsProvider::class);
        $provider->shouldReceive('refreshToken')
            ->twice()
            ->andThrow(new RequestException(
                'Rejected grant',
                new Request('POST', 'https://sso.test/oauth/token'),
                new Response(400, [], '{"error":"invalid_grant"}'),
            ));

        Socialite::shouldReceive('driver')->with('uzairports')->andReturn($provider);

        $this->assertFalse((new RefreshAccessToken)($first));
        $this->assertFalse((new RefreshAccessToken)($second));
    }

    /**
     * The cooldown answers from the row, so a login renewed just before the
     * outage is adopted rather than refused.
     */
    public function test_a_login_renewed_elsewhere_is_adopted_while_the_provider_is_left_alone(): void
    {
        $this->tripOnTheFirstFailure();

        $failing = $this->expiredToken('cooldown-adopt-first');
        $token = $this->expiredToken('cooldown-adopt-second');

        $provider = Mockery::mock(UzairportsProvider::class);
        $provider->shouldReceive('refreshToken')->once()->andThrow($this->unreachable());

        Socialite::shouldReceive('driver')->with('uzairports')->andReturn($provider);

        $this->assertUnavailable(fn (): bool => (new RefreshAccessToken)($failing));

        $this->winnerStores($token, 'winner_access', 'winner_refresh');

        $this->assertTrue((new RefreshAccessToken)($token));
        $this->assertSame('winner_access', $token->access_token);
    }

    /**
     * A login ended elsewhere is still ended during the cooldown.
     *
     * The 503 is for a login that is still due a renewal; a row that is gone
     * has to reach the middleware as the refusal it is, outage or no outage.
     */
    public function test_a_login_ended_elsewhere_is_refused_while_the_provider_is_left_alone(): void
    {
        $this->tripOnTheFirstFailure();

        $failing = $this->expiredToken('cooldown-gone-first');
        $token = $this->expiredToken('cooldown-gone-second');

        $provider = Mockery::mock(UzairportsProvider::class);
        $provider->shouldReceive('refreshToken')->once()->andThrow($this->unreachable());

        Socialite::shouldReceive('driver')->with('uzairports')->andReturn($provider);

        $this->assertUnavailable(fn (): bool => (new RefreshAccessToken)($failing));

        OauthToken::query()->whereKey($token->getKey())->delete();

        $this->assertFalse((new RefreshAccessToken)($token));
    }

    public function test_a_cooldown_of_zero_calls_the_provider_on_every_renewal(): void
    {
        RefreshAccessToken::forgetProviderFailure();
        config()->set('uzairports.provider_cooldown', 0);

        $first = $this->expiredToken('no-cooldown-first');
        $second = $this->expiredToken('no-cooldown-second');

        $provider = Mockery::mock(UzairportsProvider::class);
        $provider->shouldReceive('refreshToken')->twice()->andThrow($this->unreachable());

        Socialite::shouldReceive('driver')->with('uzairports')->andReturn($provider);

        $this->assertUnavailable(fn (): bool => (new RefreshAccessToken)($first));
        $this->assertUnavailable(fn (): bool => (new RefreshAccessToken)($second));
    }

    /**
     * A driver of the wrong type is named, and nobody is signed out over it.
     *
     * `Socialite::driver('uzairports')` hands back whatever is registered under
     * that name. The annotation that used to stand in for a check promised a
     * type nobody verified: what arrived instead reached `refreshToken()` and
     * raised an `Error` the exchange caught as an ordinary failure, so the log
     * said the identity provider had refused a token it was never asked about.
     */
    public function test_a_driver_of_the_wrong_type_refuses_the_renewal_without_ending_the_login(): void
    {
        RefreshAccessToken::forgetProviderFailure();
        Event::fake([UzairTokenRefreshFailed::class]);

        $token = $this->expiredToken('wrong-driver');

        Socialite::shouldReceive('driver')->with('uzairports')->andReturn(new stdClass);

        Log::shouldReceive('warning')->once()->withArgs(
            fn (string $message, array $context): bool => str_contains($message, 'cannot renew')
                && $context['found'] === 'stdClass'
                && $context['expected'] === UzairportsProvider::class
        );

        $this->assertUnavailable(fn (): bool => (new RefreshAccessToken)($token));

        // A misconfiguration must not sign anybody out: the application it
        // would send them back to cannot sign them in either.
        $this->assertModelExists($token);
        Event::assertDispatched(UzairTokenRefreshFailed::class);
    }

    /**
     * Ask for the first failure to be enough, for a test about the cooldown
     * rather than about how many failures reach it.
     */
    private function tripOnTheFirstFailure(): void
    {
        RefreshAccessToken::forgetProviderFailure();
        config()->set('uzairports.provider_failure_threshold', 1);
    }

    /**
     * An identity provider that never answered the exchange.
     */
    private function unreachable(): ConnectException
    {
        return new ConnectException(
            'Connection timed out',
            new Request('POST', 'https://sso.test/oauth/token'),
        );
    }

    /**
     * Assert the renewal was refused as temporarily unavailable.
     *
     * @param  callable(): bool  $renew
     */
    private function assertUnavailable(callable $renew): void
    {
        try {
            $renew();
        } catch (ServiceUnavailableHttpException) {
            $this->addToAssertionCount(1);

            return;
        }

        $this->fail('The renewal was expected to be refused as temporarily unavailable.');
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
