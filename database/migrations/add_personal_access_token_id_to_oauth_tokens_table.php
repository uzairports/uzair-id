<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * The name this upgrade gives the index it adds beside the column.
     *
     * It is the evidence `down()` goes by: the creation migration spells the
     * same column with Laravel's conventional index name, and a column cannot
     * be asked which migration wrote it.
     */
    private const string UPGRADE_UNIQUE = 'uzairid_access_token_upgrade_unique';

    /**
     * Run the migrations.
     *
     * A login issued to a mobile client names no browser session — it names the
     * Sanctum token the client was handed for it instead. Without the column a
     * request carrying such a token could only be matched against "the most
     * recent login without a session", which is whichever phone signed in last:
     * two devices of one account would share, and spend, one grant.
     *
     * Unique, because one Sanctum token stands for one login. Several nulls are
     * not collapsed by it, so the browser logins beside it are untouched.
     *
     * Installations created after this release already have the column from
     * the creation migration, so it is added only where it is missing.
     */
    public function up(): void
    {
        if (Schema::hasColumn('oauth_tokens', 'personal_access_token_id')) {
            return;
        }

        Schema::table('oauth_tokens', function (Blueprint $table) {
            $table->unsignedBigInteger('personal_access_token_id')->nullable()->after('session_id');
            $table->unique('personal_access_token_id', self::UPGRADE_UNIQUE);
        });
    }

    /**
     * Reverse the migrations, but only where they were the ones applied.
     *
     * `up()` skips a table that already has the column, so this skips the same
     * tables: without the upgrade's own index name there is no proof this
     * migration wrote the column, and dropping one the creation migration wrote
     * would sign every mobile client out.
     */
    public function down(): void
    {
        if (! Schema::hasIndex('oauth_tokens', self::UPGRADE_UNIQUE)) {
            return;
        }

        Schema::table('oauth_tokens', function (Blueprint $table) {
            $table->dropUnique(self::UPGRADE_UNIQUE);
            $table->dropColumn('personal_access_token_id');
        });
    }
};
