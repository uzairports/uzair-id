<?php

namespace Uzairports\Uzairid\Tests;

use Illuminate\Auth\AuthenticationException;
use Illuminate\Contracts\Session\Session as SessionContract;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Session;
use Symfony\Component\HttpFoundation\Response;
use Uzairports\Uzairid\Actions\RefreshAccessToken;
use Uzairports\Uzairid\Http\Middleware\EnsureAccessTokenIsFresh;

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
     * A route name that resolves to nothing used to raise a
     * `RouteNotFoundException` while building the redirect — a 500 in place of
     * the answer, at the one moment the user most needs to be sent back
     * through SSO.
     */
    public function test_an_unregistered_login_route_still_ends_in_an_authentication_failure(): void
    {
        config(['uzairports.login_route' => 'route-that-does-not-exist']);

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

        $session = Session::driver();
        $session->start();

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
        $user = TestUser::create(['uzair_id' => '4006']);

        $session = Session::driver();
        $session->start();

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

    private function handle(Request $request): Response
    {
        return (new EnsureAccessTokenIsFresh(new RefreshAccessToken))
            ->handle($request, fn () => response('OK'));
    }

    private function statelessRequest(TestUser $user): Request
    {
        $request = Request::create('/api/data');
        $request->setUserResolver(fn () => $user);

        return $request;
    }

    private function sessionRequest(TestUser $user, SessionContract $session): Request
    {
        $request = Request::create('/protected');
        $request->setLaravelSession($session);
        $request->setUserResolver(fn () => $user);

        return $request;
    }
}
