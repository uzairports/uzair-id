<?php

namespace Uzairports\Uzairid\Tests;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\Test;

/**
 * @method void up()
 * @method void down()
 */
abstract class RunnableMigration extends Migration {}

class PackageMigrationsTest extends TestCase
{
    public function test_upgrade_rollbacks_preserve_indexes_with_custom_names(): void
    {
        foreach (['session_id' => 'index_oauth_tokens_by_session', 'updated_at' => 'index_oauth_tokens_for_pruning'] as $column => $migration) {
            Schema::table('oauth_tokens', function (Blueprint $table) use ($column): void {
                $table->dropIndex([$column]);
                $table->index($column, "custom_{$column}_index");
            });

            $this->migration($migration)->up();
            $this->migration($migration)->down();

            $this->assertTrue(Schema::hasIndex('oauth_tokens', "custom_{$column}_index"));
            $indexes = array_filter(Schema::getIndexes('oauth_tokens'), fn (array $index): bool => $index['columns'] === [$column]);
            $this->assertCount(1, $indexes);
        }
    }

    public function test_upgrade_rollbacks_preserve_indexes_from_the_create_migration(): void
    {
        foreach (['session_id' => 'index_oauth_tokens_by_session', 'updated_at' => 'index_oauth_tokens_for_pruning'] as $column => $migration) {
            $this->migration($migration)->up();
            $this->migration($migration)->down();

            $this->assertTrue(Schema::hasIndex('oauth_tokens', "oauth_tokens_{$column}_index"));
        }
    }

    /**
     * @return RunnableMigration
     */
    private function migration(string $name): Migration
    {
        /** @var RunnableMigration $migration */
        $migration = require __DIR__."/../database/migrations/{$name}.php";

        return $migration;
    }

    private function createStandardUsersTable(): void
    {
        Schema::dropIfExists('oauth_tokens');
        Schema::dropIfExists('users');

        Schema::create('users', function (Blueprint $table): void {
            $table->id();
            $table->string('name');
            $table->string('email')->unique();
            $table->string('password');
            $table->timestamps();
        });
    }

    #[Test]
    public function test_primary_migrations_create_oauth_tokens_and_add_uzair_id(): void
    {
        $this->createStandardUsersTable();

        $addUzairId = $this->migration('add_uzair_id_to_users_table');
        $createTokens = $this->migration('create_oauth_tokens_table');

        $this->assertFalse(Schema::hasColumn('users', 'uzair_id'));
        $this->assertFalse(Schema::hasTable('oauth_tokens'));

        $addUzairId->up();
        $createTokens->up();

        $this->assertTrue(Schema::hasColumn('users', 'uzair_id'));
        $this->assertTrue(Schema::hasTable('oauth_tokens'));
        $this->assertTrue(Schema::hasColumns('oauth_tokens', [
            'id',
            'user_id',
            'access_token',
            'refresh_token',
            'expires_at',
            'session_id',
            'ip_address',
            'user_agent',
            'created_at',
            'updated_at',
        ]));

        DB::table('users')->insert([
            'id' => 1,
            'uzair_id' => 'uzair-001',
            'name' => 'Alisher',
            'email' => 'alisher@uzairports.com',
            'password' => 'secret',
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        DB::table('oauth_tokens')->insert([
            'user_id' => 1,
            'access_token' => 'access_tok_123',
            'refresh_token' => 'refresh_tok_123',
            'session_id' => 'session-1',
            'ip_address' => '127.0.0.1',
            'user_agent' => 'PHPUnit',
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        $this->assertDatabaseHas('oauth_tokens', ['user_id' => 1, 'session_id' => 'session-1']);

        // Idempotency check: running up() again does not throw
        $addUzairId->up();
        $this->assertTrue(Schema::hasColumn('users', 'uzair_id'));
    }

    #[Test]
    public function test_user_migrations_relax_email_and_remove_password(): void
    {
        $this->createStandardUsersTable();

        $relaxEmail = $this->migration('relax_email_column_on_users_table');
        $removePassword = $this->migration('remove_password_column_from_users_table');

        $relaxEmail->up();
        $removePassword->up();

        $this->assertFalse(Schema::hasColumn('users', 'password'));

        // Verify email is nullable and can contain duplicates
        DB::table('users')->insert([
            'name' => 'User One',
            'email' => null,
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        DB::table('users')->insert([
            'name' => 'User Two',
            'email' => null,
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        DB::table('users')->insert([
            'name' => 'User Three',
            'email' => 'duplicate@example.com',
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        DB::table('users')->insert([
            'name' => 'User Four',
            'email' => 'duplicate@example.com',
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        $this->assertSame(4, DB::table('users')->count());

        // Idempotency: re-running up() when password is gone and email is relaxed does not throw
        $relaxEmail->up();
        $removePassword->up();
        $this->assertFalse(Schema::hasColumn('users', 'password'));
    }

    #[Test]
    public function test_rollback_down_methods_revert_changes(): void
    {
        $this->createStandardUsersTable();

        $addUzairId = $this->migration('add_uzair_id_to_users_table');
        $createTokens = $this->migration('create_oauth_tokens_table');
        $relaxEmail = $this->migration('relax_email_column_on_users_table');
        $removePassword = $this->migration('remove_password_column_from_users_table');

        $addUzairId->up();
        $createTokens->up();
        $relaxEmail->up();
        $removePassword->up();

        // Rollback remove_password
        $removePassword->down();
        $this->assertTrue(Schema::hasColumn('users', 'password'));

        // Roll back relax_email (table is empty, so unique not-null is safe to restore)
        $relaxEmail->down();
        $columns = Schema::getColumns('users');
        $emailCol = collect($columns)->firstWhere('name', 'email');
        $this->assertNotNull($emailCol);
        $this->assertFalse($emailCol['nullable']);

        // Rollback add_uzair_id
        $addUzairId->down();
        $this->assertFalse(Schema::hasColumn('users', 'uzair_id'));

        // Rollback create_oauth_tokens
        $createTokens->down();
        $this->assertFalse(Schema::hasTable('oauth_tokens'));
    }

    #[Test]
    public function test_upgrade_migrations_migrate_legacy_oauth_tokens_table(): void
    {
        Schema::dropIfExists('oauth_tokens');
        Schema::dropIfExists('users');

        Schema::create('users', function (Blueprint $table): void {
            $table->id();
            $table->string('name');
            $table->timestamps();
        });

        // Simulate legacy v1.x table (unique user_id, no session_id, no ip_address, no user_agent)
        Schema::create('oauth_tokens', function (Blueprint $table): void {
            $table->id();
            $table->foreignId('user_id')->unique();
            $table->text('access_token');
            $table->text('refresh_token')->nullable();
            $table->timestamp('expires_at')->nullable();
            $table->timestamps();
        });

        $addSessionId = $this->migration('add_session_id_to_oauth_tokens_table');
        $makePerSession = $this->migration('make_oauth_tokens_per_session');

        $this->assertFalse(Schema::hasColumn('oauth_tokens', 'session_id'));
        $this->assertFalse(Schema::hasColumn('oauth_tokens', 'ip_address'));
        $this->assertFalse(Schema::hasColumn('oauth_tokens', 'user_agent'));

        // Step 1: add_session_id migration
        $addSessionId->up();
        $this->assertTrue(Schema::hasColumn('oauth_tokens', 'session_id'));

        // Insert rows: one without session_id (should be pruned by make_oauth_tokens_per_session)
        DB::table('oauth_tokens')->insert([
            'user_id' => 1,
            'access_token' => 'legacy_token',
            'session_id' => null,
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        // Step 2: make_oauth_tokens_per_session migration
        $makePerSession->up();

        // Stale token with session_id = null should have been deleted
        $this->assertSame(0, DB::table('oauth_tokens')->count());
        $this->assertTrue(Schema::hasColumn('oauth_tokens', 'ip_address'));
        $this->assertTrue(Schema::hasColumn('oauth_tokens', 'user_agent'));

        // Now multiple sessions per user are allowed
        DB::table('oauth_tokens')->insert([
            'user_id' => 1,
            'access_token' => 'token_desktop',
            'session_id' => 'sess-desktop',
            'ip_address' => '1.1.1.1',
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        DB::table('oauth_tokens')->insert([
            'user_id' => 1,
            'access_token' => 'token_mobile',
            'session_id' => 'sess-mobile',
            'ip_address' => '2.2.2.2',
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        $this->assertSame(2, DB::table('oauth_tokens')->where('user_id', 1)->count());

        // Test rollbacks of upgrade migrations
        // Clean up rows to allow re-applying unique(user_id)
        DB::table('oauth_tokens')->where('session_id', 'sess-mobile')->delete();

        $makePerSession->down();
        $this->assertFalse(Schema::hasColumn('oauth_tokens', 'ip_address'));
        $this->assertFalse(Schema::hasColumn('oauth_tokens', 'user_agent'));

        $addSessionId->down();
        $this->assertFalse(Schema::hasColumn('oauth_tokens', 'session_id'));
    }

    /**
     * `OauthToken::prunable()` sweeps the table by `updated_at` alone — the one
     * query the package makes without a `user_id` beside it, and so the only
     * one the unique pair does not already serve.
     */
    #[Test]
    public function test_created_oauth_tokens_are_indexed_for_pruning(): void
    {
        $this->createStandardUsersTable();

        $this->migration('add_uzair_id_to_users_table')->up();
        $this->migration('create_oauth_tokens_table')->up();

        $this->assertTrue($this->hasIndexOn('oauth_tokens', ['updated_at']));
    }

    /**
     * The callback looks a login up by session id alone — the row may belong to
     * another account — so the unique pair, which leads with `user_id`, cannot
     * serve it.
     */
    #[Test]
    public function test_created_oauth_tokens_are_indexed_by_session(): void
    {
        $this->createStandardUsersTable();

        $this->migration('add_uzair_id_to_users_table')->up();
        $this->migration('create_oauth_tokens_table')->up();

        $this->assertTrue($this->hasIndexOn('oauth_tokens', ['session_id']));
    }

    #[Test]
    public function test_the_upgrade_migration_indexes_a_table_created_before_the_session_index_existed(): void
    {
        Schema::dropIfExists('oauth_tokens');

        Schema::create('oauth_tokens', function (Blueprint $table): void {
            $table->id();
            $table->foreignId('user_id');
            $table->text('access_token');
            $table->string('session_id')->nullable();
            $table->timestamps();

            // The pair the create migration has carried all along. It leads
            // with `user_id`, so it must not be mistaken for the index a
            // session-only lookup needs.
            $table->unique(['user_id', 'session_id']);
        });

        $indexBySession = $this->migration('index_oauth_tokens_by_session');

        $this->assertFalse($this->hasIndexOn('oauth_tokens', ['session_id']));

        $indexBySession->up();
        $this->assertTrue($this->hasIndexOn('oauth_tokens', ['session_id']));

        // Idempotency: an installation that already carries the index — from
        // the create migration or by hand — is left alone.
        $indexBySession->up();
        $this->assertTrue($this->hasIndexOn('oauth_tokens', ['session_id']));

        $this->migration('index_oauth_tokens_by_session')->down();
        $this->assertFalse($this->hasIndexOn('oauth_tokens', ['session_id']));
    }

    #[Test]
    public function test_the_upgrade_migration_indexes_a_table_created_before_the_index_existed(): void
    {
        Schema::dropIfExists('oauth_tokens');

        Schema::create('oauth_tokens', function (Blueprint $table): void {
            $table->id();
            $table->foreignId('user_id');
            $table->text('access_token');
            $table->timestamps();
        });

        $indexForPruning = $this->migration('index_oauth_tokens_for_pruning');

        $this->assertFalse($this->hasIndexOn('oauth_tokens', ['updated_at']));

        $indexForPruning->up();
        $this->assertTrue($this->hasIndexOn('oauth_tokens', ['updated_at']));

        // Idempotency: an installation that already carries the index — from
        // the create migration or by hand — is left alone.
        $indexForPruning->up();
        $this->assertTrue($this->hasIndexOn('oauth_tokens', ['updated_at']));

        $this->migration('index_oauth_tokens_for_pruning')->down();
        $this->assertFalse($this->hasIndexOn('oauth_tokens', ['updated_at']));
    }

    /**
     * @param  list<string>  $columns
     */
    private function hasIndexOn(string $table, array $columns): bool
    {
        foreach (Schema::getIndexes($table) as $index) {
            if ($index['columns'] === $columns) {
                return true;
            }
        }

        return false;
    }

    #[Test]
    public function test_create_oauth_tokens_supports_string_user_key(): void
    {
        Schema::dropIfExists('oauth_tokens');

        config()->set('auth.providers.users.model', StringKeyUser::class);

        $createTokens = $this->migration('create_oauth_tokens_table');
        $createTokens->up();

        $this->assertTrue(Schema::hasTable('oauth_tokens'));

        $columns = Schema::getColumns('oauth_tokens');
        $userIdCol = collect($columns)->firstWhere('name', 'user_id');
        $this->assertNotNull($userIdCol);
        // `type_name`, not `type`: Postgres spells the full type `character
        // varying(255)`, where MySQL and SQLite say `varchar`. The name behind
        // it is `varchar` on all three.
        $this->assertStringContainsString('varchar', strtolower($userIdCol['type_name']));
        $this->assertFalse($this->hasIndexOn('oauth_tokens', ['user_id']));
        $this->assertTrue($this->hasIndexOn('oauth_tokens', ['user_id', 'session_id']));

        $createTokens->down();
    }
}

class StringKeyUser extends Model
{
    protected $table = 'users';

    protected $keyType = 'string';
}
