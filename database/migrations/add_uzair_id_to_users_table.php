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
     * The SSO id is the only stable identifier of an account: the user can change
     * the name and e-mail address at any time on the identity provider. It is
     * stored as a string because the provider treats it as an opaque value, and
     * it is nullable so that accounts created before the package was installed
     * can be linked on their owner's next sign-in.
     *
     * The column is guarded because this table belongs to the host application,
     * which may already carry it.
     *
     * Which table that is, and what its key is called, are read off the
     * configured model rather than assumed — the same way
     * `create_oauth_tokens_table` reads them. Both were spelled `users` and `id`
     * here, and an application that keeps its accounts anywhere else had this
     * migration reach for a table it does not have. On MySQL the key was worse
     * than the table: `after('id')` is emitted into the statement, so a model
     * keyed by anything but `id` failed the migration outright with error 1054.
     */
    public function up(): void
    {
        $table = $this->accountsTable();

        if ($table === null || Schema::hasColumn($table, 'uzair_id')) {
            return;
        }

        $after = $this->keyColumn($table);

        Schema::table($table, function (Blueprint $accounts) use ($after) {
            $column = $accounts->string('uzair_id')->nullable()->unique();

            if ($after !== null) {
                $column->after($after);
            }
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        $table = $this->accountsTable();

        if ($table === null || ! Schema::hasColumn($table, 'uzair_id')) {
            return;
        }

        Schema::table($table, function (Blueprint $accounts) {
            $accounts->dropUnique(['uzair_id']);
            $accounts->dropColumn('uzair_id');
        });
    }

    /**
     * The table the host application keeps its accounts in.
     *
     * Null where there is nothing to alter: the table is the application's to
     * publish, and a migration that runs before it exists has no column to add
     * to it. Laravel's own `users` stand in wherever the configured model
     * cannot be read, which is what this migration always assumed.
     */
    private function accountsTable(): ?string
    {
        $model = $this->userModel();

        $table = $model instanceof Model ? $model->getTable() : 'users';

        return Schema::hasTable($table) ? $table : null;
    }

    /**
     * The column the SSO id is written besides, where there is one to name.
     *
     * Position is cosmetic, and MySQL is the only driver given it, but naming a
     * column that is not there is no cosmetic at all: MySQL refuses the whole
     * statement. So the key is asked for by name and then checked, and a table
     * whose key this migration cannot find simply gets the column appended.
     */
    private function keyColumn(string $table): ?string
    {
        $model = $this->userModel();

        if (! $model instanceof Model) {
            return Schema::hasColumn($table, 'id') ? 'id' : null;
        }

        $key = $model->getKeyName();

        return Schema::hasColumn($table, $key) ? $key : null;
    }

    /**
     * The configured user model, or null where the application names none.
     */
    private function userModel(): ?Model
    {
        $model = config('auth.providers.users.model');

        if (! is_string($model) || ! class_exists($model)) {
            return null;
        }

        $user = new $model;

        return $user instanceof Model ? $user : null;
    }
};
