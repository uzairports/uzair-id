<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Run the migrations.
     *
     * A row stops being "the account's token" and becomes "one login": the same
     * account may hold several at once, one per browser session, each with the
     * grant that browser was issued. What has to be unique is therefore the
     * pair, not the user.
     *
     * Rows that predate the change name no session and cannot be told apart
     * once the pair becomes the identity, so they are dropped: what they hold
     * is an access token for a browser nobody can point at any more, and its
     * owner signs in again.
     *
     * Every step is guarded — an installation created after this release
     * already has the shape from the create migration.
     */
    public function up(): void
    {
        if (Schema::hasIndex('oauth_tokens', ['user_id'], 'unique')) {
            DB::table('oauth_tokens')->whereNull('session_id')->delete();

            Schema::table('oauth_tokens', function (Blueprint $table) {
                $table->dropUnique(['user_id']);
                $table->unique(['user_id', 'session_id']);
            });
        }

        Schema::table('oauth_tokens', function (Blueprint $table) {
            if (! Schema::hasColumn('oauth_tokens', 'ip_address')) {
                $table->string('ip_address', 45)->nullable()->after('session_id');
            }

            if (! Schema::hasColumn('oauth_tokens', 'user_agent')) {
                $table->text('user_agent')->nullable()->after('ip_address');
            }
        });
    }

    /**
     * Reverse the migrations.
     *
     * Only reversible while no account holds more than one login, which is the
     * whole point of the change: the rows the second device left behind have
     * nowhere to go under a unique `user_id`.
     */
    public function down(): void
    {
        Schema::table('oauth_tokens', function (Blueprint $table) {
            if (Schema::hasColumn('oauth_tokens', 'user_agent')) {
                $table->dropColumn('user_agent');
            }

            if (Schema::hasColumn('oauth_tokens', 'ip_address')) {
                $table->dropColumn('ip_address');
            }
        });

        if (Schema::hasIndex('oauth_tokens', ['user_id', 'session_id'], 'unique')) {
            Schema::table('oauth_tokens', function (Blueprint $table) {
                $table->dropUnique(['user_id', 'session_id']);
                $table->unique('user_id');
            });
        }
    }
};
