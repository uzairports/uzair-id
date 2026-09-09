<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Run the migrations.
     *
     * Signing in ends the login the same browser was holding a moment ago, and
     * looks it up by the session id it had before the handshake regenerated it.
     * That row may belong to another account — a shared computer, a second
     * identity — so the lookup cannot be scoped to the account, which is what
     * makes it the one write path the unique pair does not serve: the pair
     * leads with `user_id`, and an index cannot be entered halfway.
     *
     * Left as it was, every sign-in read `oauth_tokens` end to end. The table
     * holds a row per live login, so that scan grows with the number of people
     * signed in — worst at exactly the hour they are all signing in.
     *
     * Installations created after this release already have the index from the
     * create migration, so it is added only where it is missing.
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
     * The dedicated name identifies an index this upgrade created. Indexes
     * from the creation migration or an older release remain owned by those
     * migrations, including when up() skipped an existing custom index.
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
     * Whether some index already covers `session_id` on its own.
     *
     * The name is not what is looked for: an installation may have added the
     * index by hand under a name of its own, and adding a second one under
     * Laravel's would cost a writing on every row for nothing.
     *
     * The unique `(user_id, session_id)` pair does not answer here and must
     * not: it leads with `user_id`, so a query naming only the session cannot
     * use it.
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
