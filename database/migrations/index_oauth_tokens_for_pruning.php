<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Run the migrations.
     *
     * Indexes `updated_at` for `OauthToken::prunable()`, which queries without
     * `user_id`. Skipped when an equivalent index exists.
     */
    public function up(): void
    {
        if ($this->hasPruningIndex()) {
            return;
        }

        Schema::table('oauth_tokens', function (Blueprint $table) {
            $table->index('updated_at', 'uzairid_pruning_upgrade_index');
        });
    }

    /**
     * Reverse the migrations.
     *
     * Drops only the index carrying this upgrade's dedicated name.
     */
    public function down(): void
    {
        if (! Schema::hasIndex('oauth_tokens', 'uzairid_pruning_upgrade_index')) {
            return;
        }

        Schema::table('oauth_tokens', function (Blueprint $table) {
            $table->dropIndex('uzairid_pruning_upgrade_index');
        });
    }

    /**
     * Whether any index, under any name, covers exactly `['updated_at']`.
     */
    private function hasPruningIndex(): bool
    {
        foreach (Schema::getIndexes('oauth_tokens') as $index) {
            if ($index['columns'] === ['updated_at']) {
                return true;
            }
        }

        return false;
    }
};
