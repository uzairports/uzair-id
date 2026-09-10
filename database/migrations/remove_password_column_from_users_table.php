<?php

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Run the migrations.
     *
     * Credentials live on the identity provider, so the column has nothing to
     * hold. It is guarded because this table belongs to the host application,
     * which may already have dropped it.
     *
     * Which table that is comes off the configured model, not from the name
     * `users` — an application keeping its accounts in `members` or `staff`
     * had this migration fail on a table it does not have. See
     * `create_oauth_tokens_table`, which has read the model all along.
     */
    public function up(): void
    {
        $table = $this->accountsTable();

        if ($table === null || ! Schema::hasColumn($table, 'password')) {
            return;
        }

        Schema::table($table, function (Blueprint $accounts) {
            $accounts->dropColumn('password');
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        $table = $this->accountsTable();

        if ($table === null || Schema::hasColumn($table, 'password')) {
            return;
        }

        Schema::table($table, function (Blueprint $accounts) {
            $accounts->string('password');
        });
    }

    /**
     * The table the host application keeps its accounts in.
     *
     * Null where there is nothing to alter: the table is the application's to
     * publish, and a migration that runs before it exists has no column to drop
     * from it.
     */
    private function accountsTable(): ?string
    {
        $model = config('auth.providers.users.model');

        $table = is_string($model) && class_exists($model) && ($user = new $model) instanceof Model
            ? $user->getTable()
            : 'users';

        return Schema::hasTable($table) ? $table : null;
    }
};
