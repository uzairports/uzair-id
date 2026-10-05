<?php

namespace Uzairports\Uzairid\Tests;

use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use Symfony\Component\HttpKernel\Exception\ServiceUnavailableHttpException;
use Uzairports\Uzairid\Actions\EnsureTokenStorageMatchesProvider;

class EnsureTokenStorageMatchesProviderTest extends TestCase
{
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
