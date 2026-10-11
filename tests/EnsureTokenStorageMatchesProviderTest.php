<?php

namespace Uzairports\Uzairid\Tests;

use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Database\QueryException;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Schema;
use Mockery;
use PDOException;
use PHPUnit\Framework\Attributes\DataProvider;
use Symfony\Component\HttpKernel\Exception\ServiceUnavailableHttpException;
use Uzairports\Uzairid\Actions\EnsureTokenStorageMatchesProvider;

class EnsureTokenStorageMatchesProviderTest extends TestCase
{
    protected function tearDown(): void
    {
        $connection = DB::getDefaultConnection();
        if (config("database.connections.{$connection}.prefix") !== '') {
            config(["database.connections.{$connection}.prefix" => '']);
            DB::purge($connection);
        }

        Schema::disableForeignKeyConstraints();
        Schema::dropIfExists('other_accounts');
        Schema::enableForeignKeyConstraints();

        parent::tearDown();
    }

    public function test_a_verified_storage_is_not_read_again(): void
    {
        $check = app(EnsureTokenStorageMatchesProvider::class);
        $check();

        // A new process finds the answer in the cache rather than the schema.
        EnsureTokenStorageMatchesProvider::flushVerified();

        $this->assertSame(0, $this->queriesDuring(fn () => $check()));
    }

    public function test_the_schema_is_read_every_time_when_the_check_is_not_trusted(): void
    {
        config(['uzairports.storage_check_ttl' => 0]);

        $check = app(EnsureTokenStorageMatchesProvider::class);
        $check();

        $this->assertGreaterThan(0, $this->queriesDuring(fn () => $check()));
    }

    public function test_a_problem_is_not_remembered(): void
    {
        $this->dropTheSanctumTokenColumn();

        $check = app(EnsureTokenStorageMatchesProvider::class);

        try {
            $check();
            $this->fail('A table without the column must be refused.');
        } catch (ServiceUnavailableHttpException) {
        }

        Schema::table('oauth_tokens', function (Blueprint $table): void {
            $table->unsignedBigInteger('personal_access_token_id')->nullable();
        });

        $check();

        $this->addToAssertionCount(1);
    }

    public function test_another_account_model_is_checked_at_once(): void
    {
        $check = app(EnsureTokenStorageMatchesProvider::class);
        $check();

        Schema::create('other_accounts', function (Blueprint $table): void {
            $table->id();
        });
        config(['auth.providers.users.model' => OtherAccount::class]);

        $this->expectException(ServiceUnavailableHttpException::class);

        $check();
    }

    public function test_forgetting_the_answer_reads_the_schema_again(): void
    {
        $check = app(EnsureTokenStorageMatchesProvider::class);
        $check();

        $this->dropTheSanctumTokenColumn();
        $check->forgetVerified();

        $this->expectException(ServiceUnavailableHttpException::class);

        $check();
    }

    public function test_a_database_failure_is_logged_and_not_shown_to_the_client(): void
    {
        $check = new class extends EnsureTokenStorageMatchesProvider
        {
            public function problem(): ?string
            {
                throw new QueryException('testing', 'select secret_column from secret_host', [], new PDOException('SQLSTATE[HY000] secret'));
            }
        };

        try {
            $check();
            $this->fail('A database failure must refuse the request.');
        } catch (ServiceUnavailableHttpException $exception) {
            $this->assertStringNotContainsString('secret', $exception->getMessage());
        }
    }

    public function test_a_configuration_problem_is_logged_and_not_shown_to_the_client(): void
    {
        Log::shouldReceive('error')->once()->with(Mockery::pattern('/personal_access_token_id/'));
        $this->dropTheSanctumTokenColumn();

        try {
            app(EnsureTokenStorageMatchesProvider::class)();
            $this->fail('A table without the column must be refused.');
        } catch (ServiceUnavailableHttpException $exception) {
            $this->assertStringNotContainsString('personal_access_token_id', $exception->getMessage());
        }
    }

    public function test_another_database_behind_the_same_connection_name_is_checked_at_once(): void
    {
        $check = app(EnsureTokenStorageMatchesProvider::class);
        $check();

        $connection = DB::getDefaultConnection();
        config(["database.connections.{$connection}.prefix" => 'tenant_']);
        DB::purge($connection);

        try {
            $this->expectException(ServiceUnavailableHttpException::class);

            $check();
        } finally {
            config(["database.connections.{$connection}.prefix" => '']);
            DB::purge($connection);
        }
    }

    /**
     * `create_oauth_tokens_table` writes `user_id` without a foreign key when
     * the accounts table does not exist yet, and the installation guide says
     * such an installation keeps working. Refusing it answered every request
     * with a 503; a column that can hold the keys is accepted and reported.
     *
     * @param  class-string<TestUser>  $model
     */
    #[DataProvider('unconstrainedOwners')]
    public function test_a_table_without_a_foreign_key_is_judged_by_what_user_id_can_hold(string $column, string $model, bool $accepted): void
    {
        config(['uzairports.storage_check_ttl' => 0, 'auth.providers.users.model' => $model]);
        $this->rebuildWithoutForeignKey($column);

        EnsureTokenStorageMatchesProvider::flushStorageWarnings();
        $log = Log::spy();

        $problem = app(EnsureTokenStorageMatchesProvider::class)->problem();

        if (! $accepted) {
            $this->assertStringContainsString('cannot hold the string keys', (string) $problem);
            $log->shouldNotHaveReceived('warning');

            return;
        }

        $this->assertNull($problem);

        // Checked on every request with the TTL at zero, and said once.
        app(EnsureTokenStorageMatchesProvider::class)();
        app(EnsureTokenStorageMatchesProvider::class)();

        $log->shouldHaveReceived('warning')->once()->withArgs(fn (string $message): bool => str_contains($message, 'no user_id foreign key'));
    }

    /** @return array<string, array{string, class-string<TestUser>, bool}> */
    public static function unconstrainedOwners(): array
    {
        return [
            'string column, integer keys' => ['string', TestUser::class, true],
            'string column, string keys' => ['string', StringKeyAccount::class, true],
            'integer column, integer keys' => ['integer', TestUser::class, true],
            'integer column, string keys' => ['integer', StringKeyAccount::class, false],
        ];
    }

    /**
     * Going without a foreign key accepts the column; one that points at
     * another accounts table is still the evidence it always was.
     */
    public function test_a_foreign_key_naming_other_accounts_is_still_refused(): void
    {
        Schema::create('other_accounts', function (Blueprint $table): void {
            $table->id();
        });
        config(['auth.providers.users.model' => OtherAccount::class]);

        $this->assertStringContainsString('but the configured provider uses', (string) app(EnsureTokenStorageMatchesProvider::class)->problem());
    }

    /**
     * The token table in the shape the create migration writes when it has
     * nothing to reference.
     */
    private function rebuildWithoutForeignKey(string $column): void
    {
        Schema::drop('oauth_tokens');
        Schema::create('oauth_tokens', function (Blueprint $table) use ($column): void {
            $table->id();
            $column === 'string' ? $table->string('user_id') : $table->unsignedBigInteger('user_id');
            $table->text('access_token');
            $table->text('refresh_token')->nullable();
            $table->timestamp('expires_at')->nullable();
            $table->string('session_id')->nullable();
            $table->unsignedBigInteger('personal_access_token_id')->nullable()->unique();
            $table->string('sid')->nullable();
            $table->text('id_token')->nullable();
            $table->timestamps();
        });
    }

    private function dropTheSanctumTokenColumn(): void
    {
        Schema::table('oauth_tokens', function (Blueprint $table): void {
            $table->dropUnique(['personal_access_token_id']);
            $table->dropColumn('personal_access_token_id');
        });
    }

    private function queriesDuring(callable $callback): int
    {
        $queries = 0;

        DB::listen(function (QueryExecuted $query) use (&$queries): void {
            $queries++;
        });

        $callback();

        return $queries;
    }
}

class OtherAccount extends TestUser
{
    protected $table = 'other_accounts';
}

class StringKeyAccount extends TestUser
{
    protected $keyType = 'string';

    public $incrementing = false;
}
