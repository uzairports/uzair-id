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
     * The identity provider does not guarantee an e-mail address at all, and the
     * same address may be reused by more than one account, so the constraints
     * Laravel ships on `users.email` no longer hold once accounts are identified
     * by their SSO id.
     *
     * Both steps are guarded: this table belongs to the host application, which
     * may already have dropped the index or relaxed the column. Skipping the
     * change in that case also preserves a custom column definition, since
     * `change()` rewrites the column from the definition given here.
     *
     * Which table it is comes off the configured model, not from the name
     * `users` — an application keeping its accounts in `members` or `staff`
     * had this migration fail on a table it does not have. A table carrying no
     * `email` column at all is left alone for the same reason: it is the
     * application's, and this migration has nothing to relax in it.
     */
    public function up(): void
    {
        $table = $this->accountsTable();

        if ($table === null) {
            return;
        }

        if (Schema::hasIndex($table, ['email'], 'unique')) {
            Schema::table($table, function (Blueprint $accounts) {
                $accounts->dropUnique(['email']);
            });
        }

        if ($this->emailIsNullable($table)) {
            return;
        }

        Schema::table($table, function (Blueprint $accounts) {
            $accounts->string('email')->nullable()->change();
        });
    }

    /**
     * Reverse the migrations.
     *
     * Only reversible while no account has a missing or duplicated address.
     */
    public function down(): void
    {
        $table = $this->accountsTable();

        if ($table === null) {
            return;
        }

        if ($this->emailIsNullable($table)) {
            Schema::table($table, function (Blueprint $accounts) {
                $accounts->string('email')->nullable(false)->change();
            });
        }

        if (Schema::hasIndex($table, ['email'], 'unique')) {
            return;
        }

        Schema::table($table, function (Blueprint $accounts) {
            $accounts->unique('email');
        });
    }

    private function emailIsNullable(string $table): bool
    {
        foreach (Schema::getColumns($table) as $column) {
            if ($column['name'] === 'email') {
                return $column['nullable'];
            }
        }

        return false;
    }

    /**
     * The table the host application keeps its accounts in, if it has an
     * address column there to relax.
     */
    private function accountsTable(): ?string
    {
        $model = config('auth.providers.users.model');

        $table = is_string($model) && class_exists($model) && ($user = new $model) instanceof Model
            ? $user->getTable()
            : 'users';

        return Schema::hasTable($table) && Schema::hasColumn($table, 'email') ? $table : null;
    }
};
