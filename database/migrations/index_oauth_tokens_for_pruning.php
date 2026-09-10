<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Run the migrations.
     *
     * `OauthToken::prunable()` is the one query the package makes without a
     * `user_id` beside it: it sweeps the table by `updated_at` alone. Every
     * other query names the account and is served by the unique pair, so on a
     * table of any size the nightly `model:prune` was the only full scan left.
     *
     * Installations created after this release already have the index from the
     * creation migration, so it is added only where it is missing.
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
     * Drop only the index named for this upgrade. A pre-existing index may
     * belong to the creation migration, an older release, or the application.
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
     * Whether some index already covers `updated_at` on its own.
     *
     * The name is not what is looked for: an installation may have added the
     * index by hand under a name of its own, and adding a second one under
     * Laravel's would cost a writing on every row for nothing.
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
