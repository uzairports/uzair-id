<?php

namespace Uzairports\Uzairid\Tests;

use Exception;
use GuzzleHttp\Exception\RequestException;
use GuzzleHttp\Promise\Create;
use GuzzleHttp\Promise\Promise;
use GuzzleHttp\Promise\PromiseInterface;
use GuzzleHttp\Psr7\Request;
use GuzzleHttp\Psr7\Response;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;
use Laravel\Socialite\Facades\Socialite;
use Mockery;
use Uzairports\Uzairid\Actions\EndSessions;
use Uzairports\Uzairid\Models\OauthToken;
use Uzairports\Uzairid\Socialite\UzairportsProvider;

class EndSessionsTest extends TestCase
{
    protected function tearDown(): void
    {
        Mockery::close();

        parent::tearDown();
    }

    public function test_every_login_is_revoked_and_dropped(): void
    {
        config(['session.driver' => 'database']);

        $user = TestUser::create(['uzair_id' => '7001']);
        $this->login($user, 'phone-session', 'phone_token');
        $this->login($user, 'desktop-session', 'desktop_token');

        $provider = Mockery::mock(UzairportsProvider::class);
        $provider->shouldReceive('logoutAsync')->with('phone_token')->once()->andReturn($this->revoked());
        $provider->shouldReceive('logoutAsync')->with('desktop_token')->once()->andReturn($this->revoked());

        Socialite::shouldReceive('driver')->with('uzairports')->andReturn($provider);

        $ended = (new EndSessions)($user->id);

        $this->assertSame(2, $ended);
        $this->assertSame(0, OauthToken::query()->count());
        $this->assertSame([], $this->storedSessionIds());
    }

    /**
     * There is nothing here to hand over: the row holds a grant this
     * application cannot open, so the identity provider is told nothing and the
     * login ends locally. It used to raise the decryption failure out of the
     * logout the user asked for, leaving them signed in with a 500.
     */
    public function test_a_login_whose_grant_will_not_open_ends_without_asking_the_provider(): void
    {
        $user = TestUser::create(['uzair_id' => '7011']);

        $token = $user->tokens()->create([
            'access_token' => 'a_token',
            'refresh_token' => 'a_refresh_token',
            'session_id' => 'a-session',
        ]);

        DB::table('oauth_tokens')->where('id', $token->id)->update([
            'access_token' => 'not-a-value-this-key-can-open',
            'refresh_token' => 'not-a-value-this-key-can-open',
        ]);

        $stored = $token->fresh();

        $this->assertNotNull($stored);

        Socialite::shouldReceive('driver')->never();

        (new EndSessions)->end($stored);

        $this->assertModelMissing($token);
    }

    public function test_one_login_can_be_spared(): void
    {
        config(['session.driver' => 'database']);

        $user = TestUser::create(['uzair_id' => '7002']);
        $this->login($user, 'phone-session', 'phone_token');
        $this->login($user, 'desktop-session', 'desktop_token');

        $provider = Mockery::mock(UzairportsProvider::class);
        $provider->shouldReceive('logoutAsync')->with('phone_token')->once()->andReturn($this->revoked());
        $provider->shouldNotReceive('logoutAsync')->with('desktop_token');

        Socialite::shouldReceive('driver')->with('uzairports')->andReturn($provider);

        $ended = (new EndSessions)($user->id, 'desktop-session');

        $this->assertSame(1, $ended);
        $this->assertSame(['desktop-session'], OauthToken::query()->pluck('session_id')->all());
        $this->assertSame(['desktop-session'], $this->storedSessionIds());
    }

    public function test_login_with_null_session_is_ended_when_another_is_spared(): void
    {
        config(['session.driver' => 'database']);

        $user = TestUser::create(['uzair_id' => '70021']);
        $user->tokens()->create([
            'access_token' => 'cli_token',
            'session_id' => null,
        ]);
        $this->login($user, 'desktop-session', 'desktop_token');

        $provider = Mockery::mock(UzairportsProvider::class);
        $provider->shouldReceive('logoutAsync')->with('cli_token')->once()->andReturn($this->revoked());
        $provider->shouldNotReceive('logoutAsync')->with('desktop_token');

        Socialite::shouldReceive('driver')->with('uzairports')->andReturn($provider);

        $ended = (new EndSessions)($user->id, 'desktop-session');

        $this->assertSame(1, $ended);
        $this->assertSame(['desktop-session'], OauthToken::query()->pluck('session_id')->all());
    }

    public function test_other_accounts_are_left_alone(): void
    {
        config(['session.driver' => 'database']);

        $user = TestUser::create(['uzair_id' => '7003']);
        $bystander = TestUser::create(['uzair_id' => '7004']);

        $this->login($user, 'their-session', 'their_token');
        $this->login($bystander, 'someone-elses-session', 'someone_elses_token');

        $provider = Mockery::mock(UzairportsProvider::class);
        $provider->shouldReceive('logoutAsync')->with('their_token')->once()->andReturn($this->revoked());

        Socialite::shouldReceive('driver')->with('uzairports')->andReturn($provider);

        (new EndSessions)($user->id);

        $this->assertSame(['someone-elses-session'], OauthToken::query()->pluck('session_id')->all());
        $this->assertSame(['someone-elses-session'], $this->storedSessionIds());
    }

    /**
     * The identity provider does not get to keep a user signed in here by being
     * unreachable.
     */
    public function test_a_refused_revocation_still_drops_the_login(): void
    {
        $user = TestUser::create(['uzair_id' => '7005']);
        $this->login($user, 'phone-session', 'phone_token');

        $provider = Mockery::mock(UzairportsProvider::class);
        $provider->shouldReceive('logoutAsync')->once()->andThrow(new Exception('SSO service unavailable'));

        Socialite::shouldReceive('driver')->with('uzairports')->andReturn($provider);

        (new EndSessions)($user->id);

        $this->assertSame(0, OauthToken::query()->count());
    }

    /**
     * Only the database driver keeps sessions somewhere this can reach. The rows
     * are gone either way, which is what the middleware reads.
     */
    public function test_a_session_store_that_cannot_be_reached_is_left_alone(): void
    {
        config(['session.driver' => 'file']);

        $user = TestUser::create(['uzair_id' => '7006']);
        $this->login($user, 'phone-session', 'phone_token');

        $provider = Mockery::mock(UzairportsProvider::class);
        $provider->shouldReceive('logoutAsync')->once()->andReturn($this->revoked());

        Socialite::shouldReceive('driver')->with('uzairports')->andReturn($provider);

        (new EndSessions)($user->id);

        $this->assertSame(0, OauthToken::query()->count());
        $this->assertSame(['phone-session'], $this->storedSessionIds());
    }

    /**
     * Nothing in OAuth promises that retiring an access token retires the
     * refresh token issued with it, and one that outlives the logout is a way
     * back into the account.
     */
    public function test_the_refresh_token_is_given_up_as_well(): void
    {
        $user = TestUser::create(['uzair_id' => '7007']);

        $user->tokens()->create([
            'access_token' => 'phone_token',
            'refresh_token' => 'phone_refresh_token',
            'session_id' => 'phone-session',
        ]);

        $provider = Mockery::mock(UzairportsProvider::class);
        $provider->shouldReceive('logoutAsync')->with('phone_token')->once()->andReturn($this->revoked());
        $provider->shouldReceive('revokeRefreshTokenAsync')->with('phone_refresh_token')->once()->andReturn($this->revoked());

        Socialite::shouldReceive('driver')->with('uzairports')->andReturn($provider);

        (new EndSessions)($user->id);

        $this->assertSame(0, OauthToken::query()->count());
    }

    /**
     * The two are surrendered independently, so a provider that refuses one
     * still hears about the other.
     */
    public function test_a_refused_access_token_does_not_spare_the_refresh_token(): void
    {
        $user = TestUser::create(['uzair_id' => '7008']);

        $user->tokens()->create([
            'access_token' => 'phone_token',
            'refresh_token' => 'phone_refresh_token',
            'session_id' => 'phone-session',
        ]);

        $provider = Mockery::mock(UzairportsProvider::class);
        $provider->shouldReceive('logoutAsync')->once()->andThrow(new Exception('SSO service unavailable'));
        $provider->shouldReceive('revokeRefreshTokenAsync')->with('phone_refresh_token')->once()->andReturn($this->revoked());

        Socialite::shouldReceive('driver')->with('uzairports')->andReturn($provider);

        (new EndSessions)($user->id);

        $this->assertSame(0, OauthToken::query()->count());
    }

    public function test_ending_single_token_drops_its_stored_session(): void
    {
        config(['session.driver' => 'database']);

        $user = TestUser::create(['uzair_id' => '7009']);
        $this->login($user, 'device-one-session', 'token_one');
        $this->login($user, 'device-two-session', 'token_two');

        $tokenOne = $user->tokens()->where('session_id', 'device-one-session')->firstOrFail();

        $provider = Mockery::mock(UzairportsProvider::class);
        $provider->shouldReceive('logoutAsync')->with('token_one')->once()->andReturn($this->revoked());

        Socialite::shouldReceive('driver')->with('uzairports')->andReturn($provider);

        (new EndSessions)->end($tokenOne);

        $this->assertSame(1, OauthToken::query()->count());
        $this->assertSame(['device-two-session'], $this->storedSessionIds());
    }

    /**
     * The remote surrender is the only part of ending a login that costs a
     * round-trip, and it is the only part that can be given up. What signs the
     * device out here — the row and the stored session — goes either way.
     */
    public function test_logins_end_without_a_remote_call_when_revocation_is_declined(): void
    {
        config(['session.driver' => 'database']);

        $user = TestUser::create(['uzair_id' => '7010']);
        $this->login($user, 'phone-session', 'phone_token');
        $this->login($user, 'desktop-session', 'desktop_token');

        Socialite::shouldReceive('driver')->never();

        $ended = (new EndSessions)($user->id, revoke: false);

        $this->assertSame(2, $ended);
        $this->assertSame(0, OauthToken::query()->count());
        $this->assertSame([], $this->storedSessionIds());
    }

    /**
     * Declining revocation must not become "spare that login": the browser the
     * caller asked to keep is still the only one left standing.
     */
    public function test_declining_revocation_still_spares_the_named_session(): void
    {
        config(['session.driver' => 'database']);

        $user = TestUser::create(['uzair_id' => '7011']);
        $this->login($user, 'phone-session', 'phone_token');
        $this->login($user, 'desktop-session', 'desktop_token');

        Socialite::shouldReceive('driver')->never();

        $ended = (new EndSessions)($user->id, 'desktop-session', revoke: false);

        $this->assertSame(1, $ended);
        $this->assertSame(['desktop-session'], OauthToken::query()->pluck('session_id')->all());
        $this->assertSame(['desktop-session'], $this->storedSessionIds());
    }

    /**
     * The account may hold any number of logins, and this runs inside a request
     * somebody is waiting on — under `single_session`, inside the callback
     * itself. Dropping the rows one at a time paid a round-trip apiece for work
     * one statement does, and where revocation is declined that was the whole
     * cost of the call.
     */
    public function test_the_rows_are_dropped_in_one_statement(): void
    {
        $user = TestUser::create(['uzair_id' => '7012']);
        $this->login($user, 'phone-session', 'phone_token');
        $this->login($user, 'desktop-session', 'desktop_token');
        $this->login($user, 'tablet-session', 'tablet_token');

        Socialite::shouldReceive('driver')->never();

        $deletes = 0;
        DB::listen(function (QueryExecuted $query) use (&$deletes): void {
            if (str_starts_with(strtolower(trim($query->sql)), 'delete from "oauth_tokens"')) {
                $deletes++;
            }
        });

        $ended = (new EndSessions)($user->id, revoke: false);

        $this->assertSame(3, $ended);
        $this->assertSame(1, $deletes);
        $this->assertSame(0, OauthToken::query()->count());
    }

    /**
     * An account holding nothing still has its stored sessions cleared: the
     * rows are what the middleware reads, but a session the store is still
     * serving is a device that never reaches it.
     */
    public function test_an_account_without_logins_still_loses_its_stored_sessions(): void
    {
        config(['session.driver' => 'database']);

        $user = TestUser::create(['uzair_id' => '7013']);

        DB::table('sessions')->insert([
            'id' => 'orphan-session',
            'user_id' => $user->id,
            'payload' => '',
            'last_activity' => now()->getTimestamp(),
        ]);

        Socialite::shouldReceive('driver')->never();

        $ended = (new EndSessions)($user->id);

        $this->assertSame(0, $ended);
        $this->assertSame([], $this->storedSessionIds());
    }

    public function test_declining_revocation_does_not_hydrate_token_models(): void
    {
        $user = TestUser::create(['uzair_id' => '7014']);
        $this->login($user, 'phone-session', 'phone_token');
        $this->login($user, 'desktop-session', 'desktop_token');

        $retrievedCount = 0;
        OauthToken::retrieved(function () use (&$retrievedCount): void {
            $retrievedCount++;
        });

        Socialite::shouldReceive('driver')->never();

        $ended = (new EndSessions)($user->id, revoke: false);

        $this->assertSame(2, $ended);
        $this->assertSame(0, $retrievedCount, 'Declining revocation must delete directly without hydrating Eloquent models.');
        $this->assertSame(0, OauthToken::query()->count());
    }

    /**
     * `sessions` is among the largest tables a busy application has, and
     * `user_id = ? or id in (…)` reads two different columns in one predicate,
     * which no index answers — so the store scanned the table. Each half is now
     * its own statement and enters the index built for the column it names.
     */
    public function test_stored_sessions_are_dropped_without_a_predicate_no_index_can_answer(): void
    {
        config(['session.driver' => 'database']);

        $user = TestUser::create(['uzair_id' => '7015']);
        $this->login($user, 'phone-session', 'phone_token');
        $this->login($user, 'desktop-session', 'desktop_token');

        Socialite::shouldReceive('driver')->never();

        $statements = [];
        DB::listen(function (QueryExecuted $query) use (&$statements): void {
            if (str_starts_with(strtolower(trim($query->sql)), 'delete from "sessions"')) {
                $statements[] = strtolower($query->sql);
            }
        });

        (new EndSessions)($user->id, revoke: false);

        $this->assertNotSame([], $statements);

        foreach ($statements as $statement) {
            $this->assertStringNotContainsString(' or ', $statement, "The store was swept by a predicate no index can answer: {$statement}");
        }

        $this->assertSame([], $this->storedSessionIds());
    }

    /**
     * Splitting the sweep in two must not turn the spared browser into a third
     * statement's collateral: it is named by neither half.
     */
    public function test_the_spared_session_survives_both_halves_of_the_sweep(): void
    {
        config(['session.driver' => 'database']);

        $user = TestUser::create(['uzair_id' => '7016']);
        $this->login($user, 'phone-session', 'phone_token');
        $this->login($user, 'desktop-session', 'desktop_token');

        // A login of this account whose stored session the store never
        // recorded against a user, so only the id names it.
        DB::table('sessions')->where('id', 'phone-session')->update(['user_id' => null]);

        Socialite::shouldReceive('driver')->never();

        $ended = (new EndSessions)($user->id, 'desktop-session', revoke: false);

        $this->assertSame(1, $ended);
        $this->assertSame(['desktop-session'], $this->storedSessionIds());
    }

    /**
     * Each revocation carries the provider's revocation timeout. Sent in turn,
     * an account on several devices waited out one timeout after another inside
     * the request a browser was holding — under `single_session`, inside the
     * callback itself. They are put on the wire together instead, so the wait is
     * the slowest of them rather than the sum.
     */
    public function test_the_grants_of_several_logins_go_out_before_any_is_waited_on(): void
    {
        $user = TestUser::create(['uzair_id' => '7017']);
        $this->login($user, 'phone-session', 'phone_token');
        $this->login($user, 'desktop-session', 'desktop_token');
        $this->login($user, 'tablet-session', 'tablet_token');

        $events = [];

        $provider = Mockery::mock(UzairportsProvider::class);
        $provider->shouldReceive('logoutAsync')->times(3)->andReturnUsing(
            function (string $token) use (&$events): PromiseInterface {
                return $this->recordedRevocation($token, $events);
            }
        );

        Socialite::shouldReceive('driver')->with('uzairports')->andReturn($provider);

        (new EndSessions)($user->id);

        $this->assertSame(3, $this->occurrencesOf('sent', $events));
        $this->assertSame(3, $this->occurrencesOf('waited', $events));
        $this->assertLessThan(
            $this->firstIndexOf('waited', $events),
            $this->lastIndexOf('sent', $events),
            'Every grant must be on the wire before the first answer is waited on.'
        );
    }

    /**
     * The two grants of one login do not decide each other either, so even a
     * single sign-out no longer pays the access token's wait and the refresh
     * token's wait end to end.
     */
    public function test_both_grants_of_one_login_go_out_together(): void
    {
        $user = TestUser::create(['uzair_id' => '7018']);

        $token = $user->tokens()->create([
            'access_token' => 'phone_token',
            'refresh_token' => 'phone_refresh_token',
            'session_id' => 'phone-session',
        ]);

        $events = [];

        $provider = Mockery::mock(UzairportsProvider::class);
        $provider->shouldReceive('logoutAsync')->once()->andReturnUsing(
            function (string $value) use (&$events): PromiseInterface {
                return $this->recordedRevocation($value, $events);
            }
        );
        $provider->shouldReceive('revokeRefreshTokenAsync')->once()->andReturnUsing(
            function (string $value) use (&$events): PromiseInterface {
                return $this->recordedRevocation($value, $events);
            }
        );

        Socialite::shouldReceive('driver')->with('uzairports')->andReturn($provider);

        (new EndSessions)->end($token);

        $this->assertSame(2, $this->occurrencesOf('sent', $events));
        $this->assertLessThan(
            $this->firstIndexOf('waited', $events),
            $this->lastIndexOf('sent', $events),
            'Both grants of a login must be on the wire before either answer is waited on.'
        );
    }

    /**
     * An account with an unusual number of logins must not open a socket per
     * login all at once, so the batch has a ceiling. Set to one it is the
     * old behaviour: send, wait, send, wait.
     */
    public function test_revocation_concurrency_bounds_what_is_in_flight_at_once(): void
    {
        config(['uzairports.revocation_concurrency' => 1]);

        $user = TestUser::create(['uzair_id' => '7019']);
        $this->login($user, 'phone-session', 'phone_token');
        $this->login($user, 'desktop-session', 'desktop_token');

        $events = [];

        $provider = Mockery::mock(UzairportsProvider::class);
        $provider->shouldReceive('logoutAsync')->times(2)->andReturnUsing(
            function (string $token) use (&$events): PromiseInterface {
                return $this->recordedRevocation($token, $events);
            }
        );

        Socialite::shouldReceive('driver')->with('uzairports')->andReturn($provider);

        (new EndSessions)($user->id);

        $this->assertSame(
            ['sent', 'waited', 'sent', 'waited'],
            array_map(fn (string $event): string => explode(':', $event)[0], $events)
        );
    }

    /**
     * A 401 on an access token is the provider saying it no longer honors what
     * it was being asked to stop honoring, which is the outcome asked for. The
     * refresh endpoint answers 200 to a token it has already retired, so a 401
     * there is a real failure and is still recorded.
     */
    public function test_an_unauthorized_access_token_is_spared_the_log_but_a_refused_refresh_token_is_not(): void
    {
        $user = TestUser::create(['uzair_id' => '7020']);

        $user->tokens()->create([
            'access_token' => 'phone_token',
            'refresh_token' => 'phone_refresh_token',
            'session_id' => 'phone-session',
        ]);

        Log::shouldReceive('warning')
            ->once()
            ->withArgs(fn (string $message, array $context): bool => $context['http_status'] === 401);

        $provider = Mockery::mock(UzairportsProvider::class);
        $provider->shouldReceive('logoutAsync')->once()->andReturn($this->refused(401));
        $provider->shouldReceive('revokeRefreshTokenAsync')->once()->andReturn($this->refused(401));

        Socialite::shouldReceive('driver')->with('uzairports')->andReturn($provider);

        (new EndSessions)($user->id);

        $this->assertSame(0, OauthToken::query()->count());
    }

    /**
     * A revocation that is refused after it was sent must not cancel the ones
     * sent beside it, nor stop the logins from ending.
     */
    public function test_one_refused_revocation_does_not_take_the_others_with_it(): void
    {
        $user = TestUser::create(['uzair_id' => '7021']);
        $this->login($user, 'phone-session', 'phone_token');
        $this->login($user, 'desktop-session', 'desktop_token');

        Log::shouldReceive('warning')->once();

        $provider = Mockery::mock(UzairportsProvider::class);
        $provider->shouldReceive('logoutAsync')->with('phone_token')->once()->andReturn($this->refused(500));
        $provider->shouldReceive('logoutAsync')->with('desktop_token')->once()->andReturn($this->revoked());

        Socialite::shouldReceive('driver')->with('uzairports')->andReturn($provider);

        $ended = (new EndSessions)($user->id);

        $this->assertSame(2, $ended);
        $this->assertSame(0, OauthToken::query()->count());
    }

    /**
     * A driver registered under this name that is not this package's is nothing
     * the grants can be handed to. Ending a login is the one thing that must not
     * fail on it: the logout the user asked for used to answer with a 500,
     * leaving them looking signed in.
     */
    public function test_a_driver_of_the_wrong_kind_is_reported_rather_than_raised(): void
    {
        $user = TestUser::create(['uzair_id' => '7022']);
        $this->login($user, 'phone-session', 'phone_token');

        Log::shouldReceive('warning')->once();

        Socialite::shouldReceive('driver')->with('uzairports')->andReturn(null);

        $ended = (new EndSessions)($user->id);

        $this->assertSame(1, $ended);
        $this->assertSame(0, OauthToken::query()->count());
    }

    /**
     * A revocation that is not answered until it is waited on, recording when it
     * was sent and when the answer was asked for.
     *
     * @param  list<string>  $events
     */
    private function recordedRevocation(string $token, array &$events): PromiseInterface
    {
        $events[] = "sent:{$token}";

        $promise = null;
        $promise = new Promise(function () use (&$promise, &$events, $token): void {
            $events[] = "waited:{$token}";

            if ($promise instanceof Promise) {
                $promise->resolve(new Response(200));
            }
        });

        return $promise;
    }

    /**
     * A revocation the identity provider refused.
     */
    private function refused(int $status): PromiseInterface
    {
        return Create::rejectionFor(new RequestException(
            'The identity provider refused the revocation.',
            new Request('POST', 'https://my.uzairports.test/revoke'),
            new Response($status)
        ));
    }

    /**
     * @param  list<string>  $events
     */
    private function occurrencesOf(string $kind, array $events): int
    {
        return count(array_filter($events, fn (string $event): bool => str_starts_with($event, "{$kind}:")));
    }

    /**
     * @param  list<string>  $events
     */
    private function firstIndexOf(string $kind, array $events): int
    {
        foreach ($events as $index => $event) {
            if (str_starts_with($event, "{$kind}:")) {
                return $index;
            }
        }

        return PHP_INT_MAX;
    }

    /**
     * @param  list<string>  $events
     */
    private function lastIndexOf(string $kind, array $events): int
    {
        $found = -1;

        foreach ($events as $index => $event) {
            if (str_starts_with($event, "{$kind}:")) {
                $found = $index;
            }
        }

        return $found;
    }

    private function login(TestUser $user, string $sessionId, string $accessToken): void
    {
        $user->tokens()->create([
            'access_token' => $accessToken,
            'session_id' => $sessionId,
        ]);

        DB::table('sessions')->insert([
            'id' => $sessionId,
            'user_id' => $user->id,
            'payload' => '',
            'last_activity' => now()->getTimestamp(),
        ]);
    }

    /**
     * @return array<int, string>
     */
    private function storedSessionIds(): array
    {
        return DB::table('sessions')
            ->orderBy('id')
            ->pluck('id')
            ->map(fn (mixed $id): string => is_string($id) ? $id : '')
            ->all();
    }
}
