<?php

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;
use Uzairports\Uzairid\Uzair;

return new class extends Migration
{
    /**
     * Run the migrations.
     *
     * Adds the SSO id, the account's only stable identifier: an opaque string,
     * nullable so existing accounts link on their next sign-in. The table and
     * key come from the configured user model, and the column is skipped when
     * the table is missing or already has it.
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
     * The configured model's accounts table, or null when it does not exist yet.
     */
    private function accountsTable(): ?string
    {
        $model = $this->userModel();

        $table = $model->getTable();

        return Schema::hasTable($table) ? $table : null;
    }

    /**
     * The model's key column to place the SSO id after, or null when it does
     * not exist. MySQL fails the whole statement on `after()` naming a missing
     * column, so only a verified column is returned.
     */
    private function keyColumn(string $table): ?string
    {
        $model = $this->userModel();

        $key = $model->getKeyName();

        return Schema::hasColumn($table, $key) ? $key : null;
    }

    /**
     * An instance of the configured user model.
     */
    private function userModel(): Model
    {
        $model = Uzair::userModel();

        return new $model;
    }
};
