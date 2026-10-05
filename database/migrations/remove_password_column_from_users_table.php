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
     * Drops `password`, since credentials live on the identity provider.
     * Skipped when the table or column is missing.
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
     * The configured model's accounts table, or null when it does not exist yet.
     */
    private function accountsTable(): ?string
    {
        $model = Uzair::userModel();

        $table = (new $model)->getTable();

        return Schema::hasTable($table) ? $table : null;
    }
};
