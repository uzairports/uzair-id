<?php

namespace Uzairports\Uzairid\Tests;

use Illuminate\Contracts\Foundation\MaintenanceMode;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Session\Store;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Str;
use Laravel\Socialite\Facades\Socialite;
use Uzairports\Uzairid\Models\OauthToken;

class ProviderCommandTest extends TestCase
{
    public function test_check_reports_a_matching_provider_without_modifying_tokens(): void
    {
        $user = TestUser::create(['uzair_id' => 'owner']);
        $token = $user->tokens()->create(['access_token' => 'access']);

        $this->assertSame(0, Artisan::call('uzair:provider'));
        $this->assertStringContainsString('matches the configured', Artisan::output());
        $this->assertModelExists($token);
    }

    public function test_check_reports_the_existing_owner_after_the_provider_changes(): void
    {
        $this->useOtherProvider();

        $this->assertSame(1, Artisan::call('uzair:provider'));
        $output = Artisan::output();
        $this->assertStringContainsString('owner is [users]', $output);
        $this->assertStringContainsString('provider uses [provider_accounts]', $output);
        $this->assertStringContainsString('--end-sessions', $output);
    }

    public function test_a_callback_cannot_reinterpret_tokens_after_a_provider_change(): void
    {
        $owner = TestUser::create(['uzair_id' => 'old-owner']);
        $token = $owner->tokens()->create(['access_token' => 'old-access']);
        $this->useOtherProvider();
        Socialite::shouldReceive('driver')->never();

        $this->get(route('uzair.callback'))->assertRedirect(url('/'))->assertSessionHasErrors('oauth');

        $this->assertGuest('other');
        $this->assertModelExists($token);
    }

    public function test_cached_logins_do_not_bypass_a_changed_storage_owner(): void
    {
        config(['uzairports.login_cache_ttl' => 60]);
        $owner = TestUser::create(['uzair_id' => 'old-owner']);
        /** @var Store $session */
        $session = app('session')->driver();
        $session->start();
        $token = $owner->tokens()->create([
            'access_token' => 'old-access', 'session_id' => $session->getId(), 'expires_at' => now()->addHour(),
        ]);
        $token->cacheLogin($session->getId());
        $this->useOtherProvider();
        $other = ProviderAccount::create(['id' => $owner->id, 'uzair_id' => 'other']);
        Route::middleware(['web', 'auth:other', 'uzair.token:other'])->get('other-protected', fn (): string => 'protected');

        $this->actingAs($other, 'other')->get('other-protected')->assertServiceUnavailable();
        $this->assertModelExists($token);
    }

    public function test_mutating_stages_require_maintenance_mode(): void
    {
        $this->mock(MaintenanceMode::class)->shouldReceive('active')->andReturnFalse();

        foreach (['--end-sessions', '--rebuild-empty'] as $stage) {
            $this->assertSame(1, Artisan::call('uzair:provider', [$stage => true]));
            $this->assertStringContainsString('Enable maintenance mode', Artisan::output());
        }
    }

    public function test_rebuild_refuses_nonempty_storage_without_revoking_or_deleting_it(): void
    {
        $this->maintenance();
        $owner = TestUser::create(['uzair_id' => 'old-owner']);
        $token = $owner->tokens()->create(['access_token' => 'old-access']);
        $this->useOtherProvider();
        Socialite::shouldReceive('driver')->never();

        $this->assertSame(1, Artisan::call('uzair:provider', ['--rebuild-empty' => true]));
        $this->assertStringContainsString('not empty', Artisan::output());
        $this->assertModelExists($token);
        $this->assertSame('users', Schema::getForeignKeys('oauth_tokens')[0]['foreign_table']);
    }

    public function test_rebuild_refuses_incoming_foreign_keys(): void
    {
        $this->maintenance();
        $this->useOtherProvider();
        Schema::create('token_references', function (Blueprint $table): void {
            $table->foreignId('token_id')->constrained('oauth_tokens');
        });

        try {
            $this->assertSame(1, Artisan::call('uzair:provider', ['--rebuild-empty' => true]));
            $this->assertStringContainsString('Another table references', Artisan::output());
            $this->assertSame('users', Schema::getForeignKeys('oauth_tokens')[0]['foreign_table']);
        } finally {
            Schema::drop('token_references');
        }
    }

    public function test_transition_ends_old_logins_then_rebuilds_empty_storage_for_a_uuid_owner(): void
    {
        $this->maintenance();
        $owner = TestUser::create(['uzair_id' => 'old-owner']);
        $token = $owner->tokens()->create(['access_token' => 'old-access', 'refresh_token' => 'old-refresh']);
        $this->acceptsRevocations();

        $this->assertSame(0, Artisan::call('uzair:provider', ['--end-sessions' => true]));
        $this->assertModelMissing($token);
        $this->useOtherProvider(uuid: true);

        $status = Artisan::call('uzair:provider', ['--rebuild-empty' => true]);
        $output = Artisan::output();
        $this->assertSame(0, $status, $output);
        $this->assertStringContainsString('previous empty table is preserved', $output);
        $this->assertSame(0, Artisan::call('uzair:provider'));

        $other = ProviderUuidAccount::create(['account_key' => Str::uuid()->toString(), 'uzair_id' => 'new-owner']);
        $login = $other->tokens()->create(['access_token' => 'new-access']);
        $this->assertTrue($login->user?->is($other));
        $other->delete();
        $this->assertModelMissing($login);
    }

    public function test_ending_logins_refuses_the_wrong_provider_and_observer_vetoes(): void
    {
        $this->maintenance();
        $owner = TestUser::create(['uzair_id' => 'owner']);
        $token = $owner->tokens()->create(['access_token' => 'access']);
        $this->useOtherProvider();
        Socialite::shouldReceive('driver')->never();

        $this->assertSame(1, Artisan::call('uzair:provider', ['--end-sessions' => true]));
        $this->assertModelExists($token);

        config(['uzairports.guard' => 'web']);
        OauthToken::deleting(fn (): bool => false);
        try {
            $this->assertSame(1, Artisan::call('uzair:provider', ['--end-sessions' => true]));
            $this->assertStringContainsString('could not be deleted', Artisan::output());
            $this->assertModelExists($token);
        } finally {
            OauthToken::flushEventListeners();
        }
    }

    private function maintenance(): void
    {
        $this->mock(MaintenanceMode::class)->shouldReceive('active')->andReturnTrue();
    }

    private function useOtherProvider(bool $uuid = false): void
    {
        Schema::dropIfExists('provider_accounts');
        Schema::create('provider_accounts', function (Blueprint $table) use ($uuid): void {
            if ($uuid) {
                $table->uuid('account_key')->primary();
            } else {
                $table->id();
            }
            $table->string('uzair_id')->nullable()->unique();
            $table->timestamps();
        });
        config([
            'uzairports.guard' => 'other',
            'auth.guards.other' => ['driver' => 'session', 'provider' => 'others'],
            'auth.providers.others' => ['driver' => 'eloquent', 'model' => $uuid ? ProviderUuidAccount::class : ProviderAccount::class],
        ]);
    }

    protected function tearDown(): void
    {
        Schema::dropIfExists('oauth_tokens');
        foreach (Schema::getTableListing(schemaQualified: false) as $table) {
            if (str_starts_with($table, 'uzair_tokens_')) {
                Schema::drop($table);
            }
        }
        Schema::dropIfExists('provider_accounts');
        parent::tearDown();
    }
}

class ProviderAccount extends TestUser
{
    protected $table = 'provider_accounts';
}

class ProviderUuidAccount extends ProviderAccount
{
    protected $primaryKey = 'account_key';

    protected $keyType = 'string';

    public $incrementing = false;
}
