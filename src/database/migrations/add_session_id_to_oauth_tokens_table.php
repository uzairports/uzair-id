<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Run the migrations.
     *
     * The column names the session that signed in last, which is what lets the
     * refresh middleware tell the current browser from one whose login has
     * since been superseded.
     *
     * It is guarded because installations that published `oauth_tokens` after
     * this release already have the column from the create migration.
     */
    public function up(): void
    {
        if (Schema::hasColumn('oauth_tokens', 'session_id')) {
            return;
        }

        Schema::table('oauth_tokens', function (Blueprint $table) {
            $table->string('session_id')->nullable()->after('expires_at');
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        if (! Schema::hasColumn('oauth_tokens', 'session_id')) {
            return;
        }

        Schema::table('oauth_tokens', function (Blueprint $table) {
            $table->dropColumn('session_id');
        });
    }
};
