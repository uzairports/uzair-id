<?php

namespace Uzairports\Uzairid\Tests;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Schema;
use Laravel\Socialite\Two\User as SocialiteUser;
use Mockery;
use Uzairports\Uzairid\Actions\EnsureTokenStorageMatchesProvider;
use Uzairports\Uzairid\Models\OauthToken;
use Uzairports\Uzairid\Uzair;

/**
 * Under PHP-FPM the process ends with the response, so nothing static survives
 * a request and none of this is needed. Under Octane the worker serves the next
 * request with whatever the last one left behind, and the package's
 * once-per-process state is then once per worker — days rather than one
 * request.
 */
class StateFlushingTest extends TestCase
{
    /**
     * The interface every terminating event Octane dispatches implements. It
     * is named rather than imported because `laravel/octane` is not installed
     * here — the dispatcher matches listeners by name, so the wiring can be
     * exercised without it.
     */
    private const OCTANE_OPERATION_TERMINATED = 'Laravel\Octane\Contracts\OperationTerminated';

    public function test_the_package_listens_for_octanes_terminating_events(): void
    {
        $this->assertTrue(Event::hasListeners(self::OCTANE_OPERATION_TERMINATED));
    }

    /**
     * The warning about an unshared login cache is said once per process, which
     * is the point of it — it sits on the hot path and a misconfigured store
     * stays misconfigured. On a worker that never forgets having said it, a
     * store misconfigured by a deploy is reported once in days.
     */
    public function test_a_terminated_operation_lets_the_login_cache_warning_be_said_again(): void
    {
        OauthToken::flushLoginCacheWarnings();

        config(['uzairports.login_cache_ttl' => 10, 'cache.default' => 'array']);

        Log::shouldReceive('warning')->twice()->with(Mockery::pattern('/memory of one process/'));

        $this->assertNull(OauthToken::cachedLogin('a-session'));

        // Same request, same worker: the line is not worth repeating.
        $this->assertNull(OauthToken::cachedLogin('a-session'));

        Event::dispatch(self::OCTANE_OPERATION_TERMINATED);

        // A new request on the same worker, which is a new process as far as
        // anything reading the log can tell.
        $this->assertNull(OauthToken::cachedLogin('a-session'));
    }

    /**
     * A `login_route` naming nothing sends everyone to the site root instead of
     * a sign-in page, and `Uzair::loginUrl()` may be called from a template on
     * every page — so the line is worth writing once and worth nothing repeated
     * on each of them, and worth writing again after a deploy.
     */
    public function test_a_terminated_operation_lets_the_login_route_warning_be_said_again(): void
    {
        Uzair::flushLoginRouteWarnings();

        config(['uzairports.login_route' => 'a.route.nobody.registered']);

        Log::shouldReceive('warning')->twice()->with(Mockery::pattern('/is not registered/'));

        $firstUrl = Uzair::loginUrl();
        $repeatedUrl = Uzair::loginUrl();

        Event::dispatch(self::OCTANE_OPERATION_TERMINATED);

        $urlAfterTermination = Uzair::loginUrl();

        $this->assertSame(url('/'), $firstUrl);
        $this->assertSame(url('/'), $repeatedUrl);
        $this->assertSame(url('/'), $urlAfterTermination);
    }

    /**
     * The resolver is registered while the application boots, the way a route
     * or a binding is. A worker that dropped it between requests would serve
     * every later one without it.
     */
    public function test_flushing_keeps_the_user_resolver(): void
    {
        $resolver = fn (SocialiteUser $user): ?Model => null;

        Uzair::resolveUserUsing($resolver);

        Uzair::flushState();

        $this->assertSame($resolver, Uzair::getUserResolver());
    }

    /**
     * The verified storage is not request state: it is keyed by everything the
     * answer depends on and lapses on its own. Dropped after every request, it
     * made each Octane request read the schema again — three queries for an
     * answer the worker already had.
     */
    public function test_a_terminated_operation_keeps_the_verified_token_storage(): void
    {
        $check = new EnsureTokenStorageMatchesProvider;
        $check();

        Event::dispatch(self::OCTANE_OPERATION_TERMINATED);

        $queries = 0;
        DB::listen(function () use (&$queries): void {
            $queries++;
        });

        Cache::flush();
        $check();

        $this->assertSame(0, $queries);
    }

    /**
     * A token table without a `user_id` foreign key is reported once per
     * process, like the other warnings here, and again on the next request a
     * worker serves.
     */
    public function test_a_terminated_operation_lets_the_storage_warning_be_said_again(): void
    {
        EnsureTokenStorageMatchesProvider::flushStorageWarnings();

        Schema::table('oauth_tokens', function (Blueprint $table): void {
            $table->dropForeign(['user_id']);
        });

        Log::shouldReceive('warning')->twice()->with(Mockery::pattern('/no user_id foreign key/'), Mockery::type('array'));

        $check = new EnsureTokenStorageMatchesProvider;

        $this->assertNull($check->problem());
        $this->assertNull($check->problem());

        Event::dispatch(self::OCTANE_OPERATION_TERMINATED);

        $this->assertNull($check->problem());
    }

    /**
     * Testbench closes Mockery itself, and folds the expectation count into the
     * assertion tally on the way — closing early here would verify the
     * expectations but leave them uncounted.
     */
    protected function tearDown(): void
    {
        OauthToken::flushLoginCacheWarnings();
        Uzair::flushLoginRouteWarnings();
        EnsureTokenStorageMatchesProvider::flushStorageWarnings();
        Uzair::resolveUserUsing(null);
        Uzair::updateUserAttributesUsing(null);

        parent::tearDown();
    }
}
