<?php

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
     */
    public function up(): void
    {
        if (Schema::hasColumn('users', 'uzair_id')) {
            return;
        }

        Schema::table('users', function (Blueprint $table) {
            $table->string('uzair_id')->nullable()->unique()->after('id');
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        if (! Schema::hasColumn('users', 'uzair_id')) {
            return;
        }

        Schema::table('users', function (Blueprint $table) {
            $table->dropUnique(['uzair_id']);
            $table->dropColumn('uzair_id');
        });
    }
};
