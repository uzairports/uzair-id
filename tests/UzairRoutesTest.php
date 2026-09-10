<?php

namespace Uzairports\Uzairid\Tests;

use Illuminate\Routing\Route as RegisteredRoute;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Route;
use Uzairports\Uzairid\Http\Controllers\UzairAuthController;
use Uzairports\Uzairid\Uzair;

/**
 * The options `Uzair::routes()` takes.
 *
 * Each test registers its own group under a prefix of its own, so what it
 * asserts on cannot be the group the test case already registered.
 */
class UzairRoutesTest extends TestCase
{
    public function test_the_prefix_can_be_given(): void
    {
        Uzair::routes(['prefix' => 'sso']);

        $this->assertSame('uzair.callback', $this->routeFor('sso/callback')->getName());
    }

    public function test_the_prefix_otherwise_comes_from_the_configuration(): void
    {
        config(['uzairports.routes.prefix' => 'identity']);

        Uzair::routes();

        $this->assertSame('uzair.logout', $this->routeFor('identity/logout')->getName());
    }

    /**
     * An application that has to change a step of the handshake extends the
     * controller and names it here.
     */
    public function test_the_controller_can_be_replaced(): void
    {
        Uzair::routes(['prefix' => 'sso', 'controller' => ExtendedAuthController::class]);

        $this->assertSame(
            ExtendedAuthController::class.'@callback',
            $this->routeFor('sso/callback')->getAction('controller'),
        );
    }

    public function test_extra_middleware_is_applied_alongside_the_limiter(): void
    {
        Uzair::routes(['prefix' => 'sso', 'middleware' => ['web']]);

        $middleware = $this->routeFor('sso/callback')->middleware();

        $this->assertContains('web', $middleware);
        $this->assertContains('throttle:uzairid', $middleware);
    }

    public function test_a_different_limiter_can_be_named(): void
    {
        Uzair::routes(['prefix' => 'sso', 'throttle' => '10,1']);

        $this->assertContains('throttle:10,1', $this->routeFor('sso/callback')->middleware());
    }

    public function test_the_routes_can_be_registered_without_a_limiter(): void
    {
        Uzair::routes(['prefix' => 'sso', 'throttle' => null]);

        $this->assertSame([], $this->routeFor('sso/callback')->middleware());
    }

    /**
     * The redirect route carries the name the refresh middleware sends a
     * session it can no longer renew to. Naming them apart would land the user
     * on a page that cannot sign them in.
     */
    public function test_the_redirect_route_is_named_after_the_configured_login_route(): void
    {
        config(['uzairports.login_route' => 'sso.login']);

        Uzair::routes(['prefix' => 'sso']);

        $this->assertSame('sso.login', $this->routeFor('sso/redirect')->getName());
    }

    /**
     * An application that keeps its own `login` points the setting elsewhere,
     * and then every template linking to SSO has to know where. Laravel gives a
     * route one name — `Route::name()` appends rather than aliases — so the name
     * is resolved rather than fixed, and a template asks for the URL.
     */
    public function test_the_sign_in_url_follows_the_configured_login_route(): void
    {
        config(['uzairports.login_route' => 'sso.login']);

        Uzair::routes(['prefix' => 'sso']);

        $this->assertSame(url('sso/redirect'), Uzair::loginUrl());
    }

    /**
     * A setting naming no registered route must not answer a sign-in link with
     * a 500, which is what `route()` does with a name it cannot find.
     */
    public function test_the_sign_in_url_falls_back_to_the_site_root(): void
    {
        config(['uzairports.login_route' => 'a.route.nobody.registered']);

        $this->assertSame(url('/'), Uzair::loginUrl());
    }

    /**
     * Two routes may carry one name and Laravel says nothing. Whichever loses
     * does so silently, and both outcomes look like a bug somewhere else: a
     * guest thrown into SSO instead of seeing the form, or a "sign in through
     * SSO" button that leads back to the page it is on.
     */
    public function test_a_name_taken_by_another_route_is_reported(): void
    {
        Route::get('the-applications-own-form', fn (): string => 'form')->name('login');

        Log::shouldReceive('warning')
            ->once()
            ->withArgs(fn (string $message, array $context): bool => str_contains($message, '[login]')
                && $context['sign_in_uri'] === 'sso/redirect'
                && $context['also_named'] === ['the-applications-own-form']);

        Uzair::routes(['prefix' => 'sso']);
    }

    /**
     * Whose route answers to the name is the question, not whether it is the
     * one object just registered — an application registering the endpoints
     * twice, under two prefixes, is doing nothing wrong and must hear nothing.
     */
    public function test_a_name_held_by_this_packages_own_redirect_is_not_reported(): void
    {
        Log::shouldReceive('warning')->never();

        Uzair::routes(['prefix' => 'sso']);
        Uzair::routes(['prefix' => 'identity']);
    }

    public function test_every_endpoint_is_registered(): void
    {
        Uzair::routes(['prefix' => 'sso']);

        $this->assertSame(['GET', 'HEAD'], $this->routeFor('sso/redirect')->methods());
        $this->assertSame(['GET', 'HEAD'], $this->routeFor('sso/callback')->methods());
        $this->assertSame(['POST'], $this->routeFor('sso/logout')->methods());
        $this->assertSame(['POST'], $this->routeFor('sso/logout-device/{token}')->methods());
    }

    /**
     * Ending every login of an account means one revocation timeout per device
     * inside a single request. The devices are ended one at a time instead, so
     * nothing here registers an endpoint that fans out.
     */
    public function test_no_endpoint_ends_every_login_at_once(): void
    {
        Uzair::routes(['prefix' => 'sso']);

        $this->assertFalse(Route::has('uzair.logoutAll'));
        $this->assertNull($this->findRoute('sso/logout-all'));
    }

    private function routeFor(string $uri): RegisteredRoute
    {
        return $this->findRoute($uri) ?? $this->fail("No route is registered for [{$uri}].");
    }

    private function findRoute(string $uri): ?RegisteredRoute
    {
        foreach (Route::getRoutes()->getRoutes() as $route) {
            if ($route->uri() === $uri) {
                return $route;
            }
        }

        return null;
    }
}

/**
 * Stands in for a host application that changes a step of the handshake.
 */
class ExtendedAuthController extends UzairAuthController {}
