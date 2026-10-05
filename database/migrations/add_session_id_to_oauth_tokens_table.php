<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Run the migrations.
     *
     * Adds the browser session a login belongs to, skipped when the column
     * already exists.
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
     * Reverse the migrations, but only where they were the ones applied.
     *
     * There is no marker index, so the column is dropped only while no index
     * uses it: the create migration always indexes it, while on an upgraded
     * table `make_oauth_tokens_per_session::down()` has already removed the pair.
     */
    public function down(): void
    {
        if (! Schema::hasColumn('oauth_tokens', 'session_id') || $this->sessionIsIndexed()) {
            return;
        }

        Schema::table('oauth_tokens', function (Blueprint $table) {
            $table->dropColumn('session_id');
        });
    }

    /**
     * Whether any index is built on `session_id`, alone or beside another column.
     */
    private function sessionIsIndexed(): bool
    {
        foreach (Schema::getIndexes('oauth_tokens') as $index) {
            if (in_array('session_id', $index['columns'], true)) {
                return true;
            }
        }

        return false;
    }
};
