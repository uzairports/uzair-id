<?php

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
     */
    public function up(): void
    {
        if (Schema::hasIndex('users', ['email'], 'unique')) {
            Schema::table('users', function (Blueprint $table) {
                $table->dropUnique(['email']);
            });
        }

        if ($this->emailIsNullable()) {
            return;
        }

        Schema::table('users', function (Blueprint $table) {
            $table->string('email')->nullable()->change();
        });
    }

    /**
     * Reverse the migrations.
     *
     * Only reversible while no account has a missing or duplicated address.
     */
    public function down(): void
    {
        if ($this->emailIsNullable()) {
            Schema::table('users', function (Blueprint $table) {
                $table->string('email')->nullable(false)->change();
            });
        }

        if (Schema::hasIndex('users', ['email'], 'unique')) {
            return;
        }

        Schema::table('users', function (Blueprint $table) {
            $table->unique('email');
        });
    }

    private function emailIsNullable(): bool
    {
        foreach (Schema::getColumns('users') as $column) {
            if ($column['name'] === 'email') {
                return $column['nullable'];
            }
        }

        return false;
    }
};
