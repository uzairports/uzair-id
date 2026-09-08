<?php

namespace Uzairports\Uzairid\Tests;

use Illuminate\Auth\AuthenticationException;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use Uzairports\Uzairid\Actions\RefreshAccessToken;
use Uzairports\Uzairid\Http\Middleware\EnsureAccessTokenIsFresh;

class EnsureAccessTokenIsFreshTest extends TestCase
{
    public function test_passes_when_token_is_fresh(): void
    {
        $user = TestUser::create(['uzair_id' => '4001']);
        $user->token()->create([
            'access_token' => 'valid_token',
            'expires_at' => now()->addHour(),
        ]);

        $middleware = new EnsureAccessTokenIsFresh(new RefreshAccessToken);
        $request = Request::create('/test');
        $request->setUserResolver(fn () => $user);

        $response = $middleware->handle($request, fn () => response('OK'));

        $this->assertSame('OK', $response->getContent());
    }

    public function test_throws_authentication_exception_without_session_crash(): void
    {
        Route::get('/login', fn () => 'login')->name('login');

        $user = TestUser::create(['uzair_id' => '4002']);
        $user->token()->create([
            'access_token' => 'expired_token',
            'refresh_token' => null,
            'expires_at' => now()->subMinute(),
        ]);

        $middleware = new EnsureAccessTokenIsFresh(new RefreshAccessToken);

        // Stateless request without session
        $request = Request::create('/api/data');
        $request->setUserResolver(fn () => $user);

        $this->expectException(AuthenticationException::class);

        $middleware->handle($request, fn () => response('OK'));
    }
}
