<?php

namespace Uzairports\Uzairid\Tests;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Log;
use Laravel\Socialite\Two\User as SocialiteUser;
use Mockery;
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

    protected function tearDown(): void
    {
        OauthToken::flushLoginCacheWarnings();
        Uzair::resolveUserUsing(null);

        Mockery::close();

        parent::tearDown();
    }
}
