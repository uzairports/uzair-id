<?php

namespace Uzairports\Uzairid\Tests;

use GuzzleHttp\Exception\RequestException;
use GuzzleHttp\Psr7\Request as GuzzleRequest;
use GuzzleHttp\Psr7\Response as GuzzleResponse;
use Illuminate\Auth\AuthenticationException;
use Illuminate\Contracts\Cache\Repository as CacheRepository;
use Illuminate\Contracts\Session\Session as SessionContract;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Session;
use Laravel\Socialite\Facades\Socialite;
use Mockery;
use RuntimeException;
use Symfony\Component\HttpFoundation\Response;
use Uzairports\Uzairid\Actions\EndSessions;
use Uzairports\Uzairid\Actions\RefreshAccessToken;
use Uzairports\Uzairid\Http\Middleware\EnsureAccessTokenIsFresh;
use Uzairports\Uzairid\Models\OauthToken;
use Uzairports\Uzairid\Socialite\UzairportsProvider;

class EnsureAccessTokenIsFreshTest extends TestCase
{
    public function test_passes_when_token_is_fresh(): void
    {
        $user = TestUser::create(['uzair_id' => '4001']);
        $user->tokens()->create([
            'access_token' => 'valid_token',
            'expires_at' => now()->addHour(),
        ]);

        $response = $this->handle($this->statelessRequest($user));

        $this->assertSame('OK', $response->getContent());
    }

    public function test_throws_authentication_exception_without_session_crash(): void
    {
        $this->acceptsRevocations();

        $user = TestUser::create(['uzair_id' => '4002']);
        $user->tokens()->create([
            'access_token' => 'expired_token',
            'refresh_token' => null,
            'expires_at' => now()->subMinute(),
        ]);

        $this->expectException(AuthenticationException::class);

        $this->handle($this->statelessRequest($user));
    }

    /**
     * A request carrying no session names no browser, so the row it is matched
     * with is whichever device signed in last — somebody else's. Refusing the
     * request is right; signing that device out over a call it never made is
     * not, and the row used to go with the refusal.
     */
    public function test_a_request_without_a_session_leaves_the_login_it_borrowed_standing(): void
    {
        $user = TestUser::create(['uzair_id' => '4010']);

        $login = $user->tokens()->create([
            'access_token' => 'the_browsers_token',
            'refresh_token' => null,
            'expires_at' => now()->subMinute(),
            'session_id' => 'the-browsers-session',
        ]);

        try {
            $this->handle($this->statelessRequest($user));

            $this->fail('A token that cannot be renewed should have been refused.');
        } catch (AuthenticationException) {
            //
        }

        $this->assertModelExists($login);
    }

    /**
     * A login is kept alive by the browser holding it, and by nothing else.
     *
     * The request used to be matched with the account's most recent login and
     * to stamp it as seen on every call, so an API client kept an abandoned
     * browser's row out of `prunable()` for as long as it kept calling — and a
     * row that is never pruned is a grant that is never surrendered.
     */
    public function test_a_request_without_a_session_does_not_keep_a_browsers_login_alive(): void
    {
        config(['session.lifetime' => 120]);

        $user = TestUser::create(['uzair_id' => '4020']);

        $login = $user->tokens()->create([
            'access_token' => 'the_browsers_token',
            'expires_at' => now()->addHour(),
            'session_id' => 'the-browsers-session',
        ]);

        $lastSeen = now()->subMinutes(200)->startOfSecond();

        $login->forceFill(['updated_at' => $lastSeen])->saveQuietly();

        try {
            $this->handle($this->statelessRequest($user));

            $this->fail('A request holding no login of its own should have been refused.');
        } catch (AuthenticationException) {
            //
        }

        $stored = $login->fresh();

        $this->assertNotNull($stored);
        $this->assertNotNull($stored->updated_at);
        $this->assertSame($lastSeen->getTimestamp(), $stored->updated_at->getTimestamp());
    }

    /**
     * `session_id` is nullable because a token can be issued outside a session,
     * and that is the row a request without a session is answered by — not
     * whichever browser happens to have signed in last.
     */
    public function test_a_request_without_a_session_is_answered_by_the_login_that_names_none(): void
    {
        $user = TestUser::create(['uzair_id' => '4021']);

        $user->tokens()->create([
            'access_token' => 'the_clients_token',
            'expires_at' => now()->addHour(),
            'session_id' => null,
        ]);

        // Written last, so the account's most recent login is this one.
        $user->tokens()->create([
            'access_token' => 'the_browsers_token',
            'refresh_token' => null,
            'expires_at' => now()->subMinute(),
            'session_id' => 'the-browsers-session',
        ]);

        $response = $this->handle($this->statelessRequest($user));

        $this->assertSame('OK', $response->getContent());
    }

    /**
     * A route name that resolves to nothing used to raise a
     * `RouteNotFoundException` while building the redirect — a 500 in place of
     * the answer, at the one moment the user most needs to be sent back
     * through SSO.
     */
    public function test_an_unregistered_login_route_still_ends_in_an_authentication_failure(): void
    {
        config(['uzairports.login_route' => 'route-that-does-not-exist']);

        $this->acceptsRevocations();

        $user = TestUser::create(['uzair_id' => '4003']);
        $user->tokens()->create([
            'access_token' => 'expired_token',
            'refresh_token' => null,
            'expires_at' => now()->subMinute(),
        ]);

        $this->expectException(AuthenticationException::class);

        $this->handle($this->statelessRequest($user));
    }

    public function test_the_session_that_owns_the_login_is_let_through(): void
    {
        $user = TestUser::create(['uzair_id' => '4004']);

        $session = $this->startedSession();

        $user->tokens()->create([
            'access_token' => 'current_token',
            'expires_at' => now()->addHour(),
            'session_id' => $session->getId(),
        ]);

        $response = $this->handle($this->sessionRequest($user, $session));

        $this->assertSame('OK', $response->getContent());
    }

    /**
     * A login belongs to the browser that made it. Another device holding one
     * says nothing about this session.
     */
    public function test_another_devices_login_does_not_count_as_this_ones(): void
    {
        $user = TestUser::create(['uzair_id' => '4005']);
        $user->tokens()->create([
            'access_token' => 'the_other_devices_token',
            'expires_at' => now()->addHour(),
            'session_id' => 'the-other-devices-session',
        ]);

        $this->actingAs($user)->get(route('protected'))->assertRedirect(route('login'));

        $this->assertGuest();
        $this->assertSame(1, $user->tokens()->count());
    }

    public function test_ending_one_device_leaves_the_others_alone(): void
    {
        $this->acceptsRevocations();

        $user = TestUser::create(['uzair_id' => '4006']);

        $session = $this->startedSession();

        $user->tokens()->create([
            'access_token' => 'this_devices_token',
            'refresh_token' => null,
            'expires_at' => now()->subMinute(),
            'session_id' => $session->getId(),
        ]);

        $user->tokens()->create([
            'access_token' => 'the_other_devices_token',
            'expires_at' => now()->addHour(),
            'session_id' => 'the-other-devices-session',
        ]);

        try {
            $this->handle($this->sessionRequest($user, $session));

            $this->fail('The login that could not be renewed should have been refused.');
        } catch (AuthenticationException) {
            //
        }

        $this->assertSame(['the-other-devices-session'], $user->tokens()->pluck('session_id')->all());
    }

    /**
     * A login the middleware ends is a login like any other, and its grants go
     * back to the identity provider.
     *
     * The row used to be deleted here and nothing else. What the exchange was
     * refused is the refresh token; the access token beside it is good for up
     * to `refresh_leeway` more seconds, and once the row was gone nothing was
     * left pointing at either of them to ever surrender them.
     */
    public function test_a_login_that_can_no_longer_be_renewed_hands_its_grants_back(): void
    {
        $user = TestUser::create(['uzair_id' => '4017']);

        $session = $this->startedSession();

        $token = $user->tokens()->create([
            'access_token' => 'the_access_token',
            'refresh_token' => 'the_refresh_token',
            'expires_at' => now()->subMinute(),
            'session_id' => $session->getId(),
        ]);

        $provider = Mockery::mock(UzairportsProvider::class);
        $provider->shouldReceive('refreshToken')->once()->andThrow(new RequestException(
            'Rejected grant',
            new GuzzleRequest('POST', 'https://sso.test/oauth/token'),
            new GuzzleResponse(400, [], '{"error":"invalid_grant"}'),
        ));
        $provider->shouldReceive('logoutAsync')->with('the_access_token')->once()->andReturn($this->revoked());
        $provider->shouldReceive('revokeRefreshTokenAsync')->with('the_refresh_token')->once()->andReturn($this->revoked());

        Socialite::shouldReceive('driver')->with('uzairports')->andReturn($provider);

        try {
            $this->handle($this->sessionRequest($user, $session));

            $this->fail('A login that cannot be renewed should have been refused.');
        } catch (AuthenticationException) {
            //
        }

        $this->assertModelMissing($token);
    }

    /**
     * A row another request has already dropped has no grants left to hand
     * back, and must not be revoked from the snapshot still held here.
     */
    public function test_a_login_already_gone_is_not_revoked_from_a_stale_snapshot(): void
    {
        $user = TestUser::create(['uzair_id' => '4018']);

        $session = $this->startedSession();

        $token = $user->tokens()->create([
            'access_token' => 'the_access_token',
            'refresh_token' => null,
            'expires_at' => now()->subMinute(),
            'session_id' => $session->getId(),
        ]);

        // Gone by the time the refusal reaches the surrender, which is what a
        // second request signing this device out looks like from here.
        OauthToken::query()->whereKey($token->getKey())->delete();

        $provider = Mockery::mock(UzairportsProvider::class);
        $provider->shouldReceive('logoutAsync')->never();
        $provider->shouldReceive('revokeRefreshTokenAsync')->never();

        Socialite::shouldReceive('driver')->with('uzairports')->andReturn($provider);

        $this->expectException(AuthenticationException::class);

        $this->handle($this->sessionRequest($user, $session));
    }

    /**
     * The identity signed out from another device, or everywhere at once, which
     * revoked the token in SSO and dropped the row. What is left here is a
     * session with nothing behind it.
     */
    public function test_a_linked_account_left_without_a_login_is_refused(): void
    {
        $user = TestUser::create(['uzair_id' => '4007']);

        $this->actingAs($user)->get(route('protected'))->assertRedirect(route('login'));

        $this->assertGuest();
    }

    public function test_an_account_the_package_never_linked_is_left_alone(): void
    {
        $user = TestUser::create(['uzair_id' => null, 'name' => 'Local Account']);

        $this->actingAs($user)->get(route('protected'))->assertStatus(200);

        $this->assertAuthenticated();
    }

    /**
     * Letting a fresh token through is the one moment the middleware learns the
     * login is still in use, and pruning has nothing else to go on.
     */
    public function test_a_login_let_through_is_kept_alive(): void
    {
        config(['session.lifetime' => 120]);

        $user = TestUser::create(['uzair_id' => '4008']);

        $session = $this->startedSession();

        $token = $user->tokens()->create([
            'access_token' => 'a_token_that_outlives_the_window',
            'expires_at' => now()->addHours(8),
            'session_id' => $session->getId(),
        ]);

        $this->travel(5)->hours();

        $this->assertSame('OK', $this->handle($this->sessionRequest($user, $session))->getContent());

        $this->assertSame(0, (new OauthToken)->prunable()->count());
        $this->assertTrue($token->fresh()?->updated_at?->greaterThan(now()->subMinute()));
    }

    /**
     * The middleware resolves the login to decide whether the session may
     * continue; a controller asking the same user for it afterward must be
     * answered from what was already read.
     */
    public function test_the_login_it_resolved_is_left_on_the_user(): void
    {
        $user = TestUser::create(['uzair_id' => '4009']);

        $session = $this->startedSession();

        $token = $user->tokens()->create([
            'access_token' => 'valid_token',
            'expires_at' => now()->addHour(),
            'session_id' => $session->getId(),
        ]);

        $request = $this->sessionRequest($user, $session);

        // What the container hands back is what the trait reads, the way it
        // does in an ordinary request. Binding it re-points the user resolver
        // at the auth guard, so the account under test is named again after.
        app()->instance('request', $request);
        $request->setUserResolver(fn () => $user);

        $this->handle($request);

        // Nothing may be read from the database a second time, so the row is
        // taken away before the question is asked again.
        DB::table('oauth_tokens')->delete();

        $this->assertTrue($token->is($user->currentToken()));
    }

    /**
     * Off by default: the row is read on every request, which is the only
     * setting under which a login ended anywhere is refused on the very next
     * one.
     */
    public function test_the_row_is_read_on_every_request_by_default(): void
    {
        $user = TestUser::create(['uzair_id' => '4011']);

        $session = $this->startedSession();

        $user->tokens()->create([
            'access_token' => 'valid_token',
            'expires_at' => now()->addHour(),
            'session_id' => $session->getId(),
        ]);

        $this->handle($this->sessionRequest($user, $session));

        $this->assertSame(1, $this->tokenReadsDuring(fn () => $this->handle($this->sessionRequest($user, $session))));
    }

    /**
     * A browser clicking around asks the same two questions of the same row on
     * every request, and gets the same answer. Given a lifetime to stand for,
     * that answer is reused and the read goes away.
     */
    public function test_a_resolved_login_answers_the_next_request_without_reading_the_row(): void
    {
        config(['uzairports.login_cache_ttl' => 10]);

        $user = TestUser::create(['uzair_id' => '4012']);

        $session = $this->startedSession();

        $user->tokens()->create([
            'access_token' => 'valid_token',
            'expires_at' => now()->addHour(),
            'session_id' => $session->getId(),
        ]);

        $this->assertSame('OK', $this->handle($this->sessionRequest($user, $session))->getContent());

        $reads = $this->tokenReadsDuring(function () use ($user, $session): void {
            $this->assertSame('OK', $this->handle($this->sessionRequest($user, $session))->getContent());
        });

        $this->assertSame(0, $reads);
    }

    /**
     * The entry stands for the row, so a login ended anywhere in the package
     * has to take it with it — otherwise the device it signed out keeps being
     * let through until the lifetime lapses.
     */
    public function test_ending_a_login_stops_its_entry_answering_for_it(): void
    {
        config(['uzairports.login_cache_ttl' => 10]);

        $user = TestUser::create(['uzair_id' => '4013']);

        $session = $this->startedSession();

        $token = $user->tokens()->create([
            'access_token' => 'valid_token',
            'expires_at' => now()->addHour(),
            'session_id' => $session->getId(),
        ]);

        $this->assertSame('OK', $this->handle($this->sessionRequest($user, $session))->getContent());

        $provider = Mockery::mock(UzairportsProvider::class);
        $provider->shouldReceive('logoutAsync')->once()->andReturn($this->revoked());

        Socialite::shouldReceive('driver')->with('uzairports')->andReturn($provider);

        (new EndSessions)->end($token);

        $this->expectException(AuthenticationException::class);

        $this->handle($this->sessionRequest($user, $session));
    }

    /**
     * A session id names a session, not an account. An entry left by whoever
     * held the session before must not answer for whoever holds it now.
     */
    public function test_an_entry_does_not_answer_for_another_account(): void
    {
        config(['uzairports.login_cache_ttl' => 10]);

        $session = $this->startedSession();

        $first = TestUser::create(['uzair_id' => '4014']);
        $first->tokens()->create([
            'access_token' => 'the_first_accounts_token',
            'expires_at' => now()->addHour(),
            'session_id' => $session->getId(),
        ]);

        $this->assertSame('OK', $this->handle($this->sessionRequest($first, $session))->getContent());

        $second = TestUser::create(['uzair_id' => '4015']);

        $this->expectException(AuthenticationException::class);

        $this->handle($this->sessionRequest($second, $session));
    }

    /**
     * An unknown expiry is not freshness — the token is renewed rather than let
     * past — so it must not be cached as though it were.
     */
    public function test_a_login_without_a_known_expiry_is_never_answered_from_an_entry(): void
    {
        config(['uzairports.login_cache_ttl' => 10]);

        $this->acceptsRevocations();

        $user = TestUser::create(['uzair_id' => '4016']);

        $session = $this->startedSession();

        $user->tokens()->create([
            'access_token' => 'a_token_of_unknown_lifetime',
            'refresh_token' => null,
            'expires_at' => null,
            'session_id' => $session->getId(),
        ]);

        try {
            $this->handle($this->sessionRequest($user, $session));

            $this->fail('A token of unknown expiry should have been treated as expired.');
        } catch (AuthenticationException) {
            //
        }

        $this->assertNull(OauthToken::cachedLogin($session->getId()));
    }

    /**
     * How many times `oauth_tokens` was read while the given work ran.
     */
    /**
     * The entry is an optimisation over reading the row, and an optimisation
     * that cannot be reached must cost the query it was saving rather than the
     * request. Left to raise, an unreachable cache answered every authenticated
     * request with a 500 — including the requests of an application that had
     * only ever turned `login_cache_ttl` on to save itself a query.
     */
    public function test_a_login_cache_that_will_not_answer_falls_back_to_the_row(): void
    {
        config(['uzairports.login_cache_ttl' => 10]);

        $user = TestUser::create(['uzair_id' => '4020']);

        $session = $this->startedSession();

        $user->tokens()->create([
            'access_token' => 'valid_token',
            'expires_at' => now()->addHour(),
            'session_id' => $session->getId(),
        ]);

        $this->loginCacheIsDown();

        $this->assertSame('OK', $this->handle($this->sessionRequest($user, $session))->getContent());

        $reads = $this->tokenReadsDuring(function () use ($user, $session): void {
            $this->assertSame('OK', $this->handle($this->sessionRequest($user, $session))->getContent());
        });

        $this->assertGreaterThan(0, $reads);
    }

    /**
     * A store that answers every call with a failure, the way an unreachable
     * Redis does.
     */
    private function loginCacheIsDown(): void
    {
        $repository = Mockery::mock(CacheRepository::class);
        $repository->shouldReceive('get', 'put', 'forget', 'deleteMultiple')
            ->andThrow(new RuntimeException('The cache store cannot be reached.'));

        Cache::shouldReceive('store')->andReturn($repository);

        OauthToken::flushLoginCacheWarnings();
    }

    private function tokenReadsDuring(callable $work): int
    {
        $reads = 0;

        DB::listen(function (QueryExecuted $query) use (&$reads): void {
            if (str_contains($this->unquotedSql($query->sql), 'from oauth_tokens')) {
                $reads++;
            }
        });

        $work();

        return $reads;
    }

    private function handle(Request $request): Response
    {
        return (new EnsureAccessTokenIsFresh(new RefreshAccessToken, new EndSessions))
            ->handle($request, fn () => response('OK'));
    }

    private function statelessRequest(TestUser $user): Request
    {
        $request = Request::create('/api/data');
        $request->setUserResolver(fn () => $user);

        return $request;
    }

    /**
     * A session with an id, which is what names a login.
     */
    private function startedSession(): SessionContract
    {
        $session = Session::driver();

        if (! $session instanceof SessionContract) {
            throw new RuntimeException('The configured session driver is not a session.');
        }

        $session->start();

        return $session;
    }

    private function sessionRequest(TestUser $user, SessionContract $session): Request
    {
        $request = Request::create('/protected');
        $request->setLaravelSession($session);
        $request->setUserResolver(fn () => $user);

        return $request;
    }
}
