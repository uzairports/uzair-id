<?php

namespace Uzairports\Uzairid\Tests;

use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Database\QueryException;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use PDOException;
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
