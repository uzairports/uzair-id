<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * The marker name for the unique pair, which `down()` relies on to prove
     * this migration converted the table; the create migration uses Laravel's
     * conventional name.
     */
    private const string UPGRADE_UNIQUE = 'uzairid_session_pair_upgrade_unique';

    /**
     * Run the migrations.
     *
     * Replaces `unique(user_id)` with a `(user_id, session_id)` pair under the
     * marker name, deleting sessionless rows, and adds the device columns.
     * Every step is skipped where the table already has that shape.
     */
    public function up(): void
    {
        if (Schema::hasIndex('oauth_tokens', ['user_id'], 'unique')) {
            DB::table('oauth_tokens')->whereNull('session_id')->delete();

            Schema::table('oauth_tokens', function (Blueprint $table) {
                $table->dropUnique(['user_id']);
                $table->unique(['user_id', 'session_id'], self::UPGRADE_UNIQUE);
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
     * Reverse the migrations, but only where they were the ones applied.
     *
     * Reverses nothing, columns included, unless the `UPGRADE_UNIQUE` marker
     * is present. Only succeeds while no account holds more than one login;
     * rows deleted by `up()` are not restored.
     */
    public function down(): void
    {
        if (! Schema::hasIndex('oauth_tokens', self::UPGRADE_UNIQUE)) {
            return;
        }

        Schema::table('oauth_tokens', function (Blueprint $table) {
            $table->dropUnique(self::UPGRADE_UNIQUE);
            $table->unique('user_id');
        });

        Schema::table('oauth_tokens', function (Blueprint $table) {
            if (Schema::hasColumn('oauth_tokens', 'user_agent')) {
                $table->dropColumn('user_agent');
            }

            if (Schema::hasColumn('oauth_tokens', 'ip_address')) {
                $table->dropColumn('ip_address');
            }
        });
    }
};
