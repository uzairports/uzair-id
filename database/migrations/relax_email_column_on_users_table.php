<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;
use Uzairports\Uzairid\Uzair;

return new class extends Migration
{
    /**
     * Run the migrations.
     *
     * Drops the unique index on `email` and makes it nullable, since the
     * identity provider guarantees neither presence nor uniqueness. Each step
     * is skipped when already done, which also preserves a custom column
     * definition that `change()` would overwrite.
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
     * The configured model's accounts table, or null when it or its `email`
     * column does not exist.
     */
    private function accountsTable(): ?string
    {
        $model = Uzair::userModel();

        $table = (new $model)->getTable();

        return Schema::hasTable($table) && Schema::hasColumn($table, 'email') ? $table : null;
    }
};
