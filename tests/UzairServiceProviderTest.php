<?php

namespace Uzairports\Uzairid\Tests;

use Illuminate\Foundation\Application;
use Illuminate\Support\ServiceProvider;
use Laravel\Socialite\Contracts\Factory;
use Laravel\Socialite\Facades\Socialite;
use Uzairports\Uzairid\Providers\UzairServiceProvider;
use Uzairports\Uzairid\Socialite\UzairportsProvider;

class UzairServiceProviderTest extends TestCase
{
    /**
     * One test needs a manager that already exists when the package boots, so
     * that the registration has to find it rather than wait for it.
     *
     * @param  Application  $app
     */
    protected function defineEnvironment($app): void
    {
        parent::defineEnvironment($app);

        if (str_contains($this->name(), 'built_before_the_package_boots')) {
            $app->make(Factory::class);
        }
    }

    /**
     * Socialite's own provider is deferred, so nothing of it is built until a
     * driver is asked for. Reaching for the manager in `boot()` undid that on
     * every request the host application served — including the overwhelming
     * majority that never touch an OAuth endpoint — because the package boots
     * on all of them and the driver is registered on a manager.
     *
     * The registration waits for a manager to be built instead.
     */
    public function test_a_migration_already_published_is_not_offered_again(): void
    {
        $published = database_path('migrations/2026_01_01_000000_index_oauth_tokens_by_session.php');
        file_put_contents($published, '<?php');

        // What a provider publishes is kept statically and only ever merged.
        ServiceProvider::$publishes = [];
        ServiceProvider::$publishGroups = [];

        try {
            $this->refreshApplication();

            $destinations = array_values(ServiceProvider::pathsToPublish(UzairServiceProvider::class, 'uzairid-upgrade-migrations'));
        } finally {
            unlink($published);
        }

        $this->assertCount(4, $destinations);
        $this->assertEmpty(array_filter($destinations, fn (string $path): bool => str_ends_with($path, '_index_oauth_tokens_by_session.php')));
    }

    public function test_booting_the_package_does_not_build_a_socialite_manager(): void
    {
        $this->assertFalse($this->app?->resolved(Factory::class));
    }

    /**
     * Waiting is only worth anything if the driver is still there when it is
     * finally asked for.
     */
    public function test_the_driver_is_registered_by_the_time_one_is_asked_for(): void
    {
        $this->assertInstanceOf(UzairportsProvider::class, Socialite::driver('uzairports'));
    }

    /**
     * A manager built before the package boots — by another provider, or by
     * anything resolving the contract early — must be extended too, or the
     * driver would simply be missing there.
     */
    public function test_a_manager_built_before_the_package_boots_is_extended_as_well(): void
    {
        $this->assertTrue($this->app?->resolved(Factory::class));
        $this->assertInstanceOf(UzairportsProvider::class, Socialite::driver('uzairports'));
    }
}
