<?php

namespace Uzairports\Uzairid\Tests;

use Illuminate\Routing\Route as RegisteredRoute;
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

    public function test_every_endpoint_is_registered(): void
    {
        Uzair::routes(['prefix' => 'sso']);

        $this->assertSame(['GET', 'HEAD'], $this->routeFor('sso/redirect')->methods());
        $this->assertSame(['GET', 'HEAD'], $this->routeFor('sso/callback')->methods());
        $this->assertSame(['POST'], $this->routeFor('sso/logout')->methods());
        $this->assertSame(['POST'], $this->routeFor('sso/logout-all')->methods());
        $this->assertSame(['POST'], $this->routeFor('sso/logout-device/{token}')->methods());
    }

    private function routeFor(string $uri): RegisteredRoute
    {
        foreach (Route::getRoutes()->getRoutes() as $route) {
            if ($route->uri() === $uri) {
                return $route;
            }
        }

        $this->fail("No route is registered for [{$uri}].");
    }
}

/**
 * Stands in for a host application that changes a step of the handshake.
 */
class ExtendedAuthController extends UzairAuthController {}
