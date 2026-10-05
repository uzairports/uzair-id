<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * The marker index name `down()` relies on to prove this migration added
     * the columns; the create migration uses Laravel's conventional name.
     */
    private const string UPGRADE_INDEX = 'uzairid_sid_upgrade_index';

    /**
     * Run the migrations.
     *
     * Adds what OpenID Connect files a login under: the identity provider's
     * session id, which back-channel logout names, and the ID token passed
     * back as `id_token_hint` on signing out. Skipped when `sid` exists.
     */
    public function up(): void
    {
        if (Schema::hasColumn('oauth_tokens', 'sid')) {
            return;
        }

        Schema::table('oauth_tokens', function (Blueprint $table) {
            $table->string('sid')->nullable();
            $table->text('id_token')->nullable();
            $table->index('sid', self::UPGRADE_INDEX);
        });
    }

    /**
     * Reverse the migrations, but only where they were the ones applied.
     *
     * Acts only when the marker index exists, so columns written by the
     * create migration are never dropped.
     */
    public function down(): void
    {
        if (! Schema::hasIndex('oauth_tokens', self::UPGRADE_INDEX)) {
            return;
        }

        Schema::table('oauth_tokens', function (Blueprint $table) {
            $table->dropIndex(self::UPGRADE_INDEX);
            $table->dropColumn(['sid', 'id_token']);
        });
    }
};
