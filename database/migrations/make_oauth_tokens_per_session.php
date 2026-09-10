<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * The name this upgrade gives the pair it puts in place of `unique(user_id)`.
     *
     * It identifies work this migration did. Laravel's conventional name would
     * not: the creation migration has spelled the same pair for several releases,
     * and an index cannot be asked which migration wrote it.
     */
    private const string UPGRADE_UNIQUE = 'uzairid_session_pair_upgrade_unique';

    /**
     * Run the migrations.
     *
     * A row stops being "the account's token" and becomes "one login": the same
     * account may hold several at once, one per browser session, each with the
     * grant that browser was issued. What has to be unique is therefore the
     * pair, not the user?
     *
     * Rows that predate the change name no session and cannot be told apart
     * once the pair becomes the identity, so they are dropped: what they hold
     * is an access token for a browser nobody can point at any more, and its
     * owner signs in again.
     *
     * Every step is guarded — an installation created after this release
     * already has the shape from the creation migration.
     *
     * The pair is given a name of this upgrade's own rather than Laravel's
     * conventional one, and that name is the whole of what `down()` goes by.
     * See there.
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
     * `up()` skips a table that already has the shape. This has to skip the
     * same tables — otherwise a migration that changed nothing rolls back by
     * dropping two columns and replacing the pair with `unique(user_id)`, which
     * is not a rollback but a downgrade of a table this migration never touched.
     * On an installation created after the release, it was the whole of what
     * `migrate:rollback` did to `oauth_tokens`: `ip_address` and `user_agent`
     * gone with the device list they hold, and every account back to one login.
     *
     * `UPGRADE_UNIQUE` is the evidence, the way `uzairid_pruning_upgrade_index`
     * and `uzairid_session_upgrade_index` are the evidence in the two index
     * upgrades beside this one. Present, this migration converted the table and
     * added the columns as part of the same step, so all of it comes back off
     * together. Absent, the table was never this migration's to change.
     *
     * An installation that ran an earlier copy of this file carries the pair
     * under Laravel's conventional name and is therefore left alone as well.
     * That errs toward keeping two nullable columns nobody reads, which is the
     * side of this worth erring on.
     *
     * Only reversible while no account holds more than one login, which is the
     * whole point of the change: the rows the second device left behind have
     * nowhere to go under a unique `user_id`. The sessionless rows `up()`
     * deleted do not come back either.
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
