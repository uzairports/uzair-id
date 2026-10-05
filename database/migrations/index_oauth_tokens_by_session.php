<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Run the migrations.
     *
     * Sign-in looks up the browser's previous login by `session_id` alone (the
     * row may belong to another account), and the unique pair leads with
     * `user_id`, so `session_id` needs its own index. Skipped when one exists.
     */
    public function up(): void
    {
        if ($this->hasSessionIndex()) {
            return;
        }

        Schema::table('oauth_tokens', function (Blueprint $table) {
            $table->index('session_id', 'uzairid_session_upgrade_index');
        });
    }

    /**
     * Reverse the migrations.
     *
     * Drops only the index carrying this upgrade's dedicated name.
     */
    public function down(): void
    {
        if (! Schema::hasIndex('oauth_tokens', 'uzairid_session_upgrade_index')) {
            return;
        }

        Schema::table('oauth_tokens', function (Blueprint $table) {
            $table->dropIndex('uzairid_session_upgrade_index');
        });
    }

    /**
     * Whether any index, under any name, covers exactly `['session_id']`.
     * The unique pair must not count, as it leads with `user_id`.
     */
    private function hasSessionIndex(): bool
    {
        foreach (Schema::getIndexes('oauth_tokens') as $index) {
            if ($index['columns'] === ['session_id']) {
                return true;
            }
        }

        return false;
    }
};
