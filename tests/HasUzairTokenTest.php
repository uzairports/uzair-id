<?php

namespace Uzairports\Uzairid\Tests;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Session\Session as SessionContract;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Session;
use RuntimeException;
use Uzairports\Uzairid\Actions\EnsureTokenStorageMatchesProvider;
use Uzairports\Uzairid\Uzair;

class HasUzairTokenTest extends TestCase
{
    /**
     * `session()->regenerate()` keeps the payload and changes the id. The
     * trait must follow the note the session keeps, as `uzair.token` does,
     * instead of answering that the browser holds no login.
     */
    public function test_a_regenerated_session_is_followed_to_its_login(): void
    {
        $user = TestUser::create(['uzair_id' => '7001']);
        $session = $this->startedSession();
        $request = $this->sessionRequest($user, $session);

        $token = $user->tokens()->create([
            'access_token' => 'browser_token',
            'expires_at' => now()->addHour(),
            'session_id' => $session->getId(),
        ]);

        Uzair::rememberSession($request);
        $session->regenerate();

        $this->assertTrue($token->is($user->currentToken()));
        $this->assertSame($session->getId(), $token->fresh()?->session_id);
    }

    /**
     * Another account's row under the previous id is not this account's login.
     */
    public function test_following_a_regenerated_session_is_scoped_to_the_account(): void
    {
        $user = TestUser::create(['uzair_id' => '7002']);
        $other = TestUser::create(['uzair_id' => '7003']);
        $session = $this->startedSession();
        $request = $this->sessionRequest($user, $session);

        $othersToken = $other->tokens()->create([
            'access_token' => 'someone_elses_token',
            'expires_at' => now()->addHour(),
            'session_id' => $session->getId(),
        ]);

        Uzair::rememberSession($request);
        $previousId = $session->getId();
        $session->regenerate();

        $this->assertNull($user->currentToken());
        $this->assertSame($previousId, $othersToken->fresh()?->session_id);
    }

    public function test_a_memoized_answer_skips_the_storage_check(): void
    {
        $user = TestUser::create(['uzair_id' => '7004']);

        $check = new class extends EnsureTokenStorageMatchesProvider
        {
            public int $calls = 0;

            public function forUser(Authenticatable $user): void
            {
                $this->calls++;
            }
        };

        app()->instance(EnsureTokenStorageMatchesProvider::class, $check);

        $user->currentToken();
        $user->currentToken();
        $user->getUzairAccessToken();

        $this->assertSame(1, $check->calls);
    }

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

        app()->instance('request', $request);

        return $request;
    }
}
