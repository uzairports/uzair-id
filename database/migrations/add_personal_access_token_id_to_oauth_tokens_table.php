<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;
use Uzairports\Uzairid\Uzair;

return new class extends Migration
{
    /**
     * The marker index name `down()` relies on to prove this migration added
     * the column; the create migration uses Laravel's conventional name.
     */
    private const string UPGRADE_UNIQUE = 'uzairid_access_token_upgrade_unique';

    /**
     * Run the migrations.
     *
     * Adds the Sanctum token id that identifies a mobile login in place of a
     * browser session. It is unique (one Sanctum token is one login; nulls do
     * not collide) and is skipped when the column already exists.
     */
    public function up(): void
    {
        if (Schema::hasColumn('oauth_tokens', 'personal_access_token_id')) {
            return;
        }

        Schema::table('oauth_tokens', function (Blueprint $table) {
            $tokenModel = Uzair::accessTokenModel();
            $isStringKey = $tokenModel !== null && class_exists($tokenModel) && (new $tokenModel)->getKeyType() === 'string';

            if ($isStringKey) {
                $table->string('personal_access_token_id', 64)->nullable()->after('session_id');
            } else {
                $table->unsignedBigInteger('personal_access_token_id')->nullable()->after('session_id');
            }

            $table->unique('personal_access_token_id', self::UPGRADE_UNIQUE);
        });
    }

    /**
     * Reverse the migrations, but only where they were the ones applied.
     *
     * Acts only when the marker index exists, so a column written by the
     * create migration is never dropped.
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
