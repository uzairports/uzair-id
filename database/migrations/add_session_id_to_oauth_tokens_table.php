<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Run the migrations.
     *
     * The column names the session that signed in last, which is what lets the
     * refresh middleware tell the current browser from one whose login has
     * since been superseded.
     *
     * It is guarded because installations that published `oauth_tokens` after
     * this release already have the column from the creation migration.
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
     * `up()` leaves a table that already has the column alone, and this has to
     * leave the same tables alone: a migration that changed nothing must not
     * roll back by dropping the column every login in the table is named by.
     *
     * What says the column is not this migration's to drop is that something
     * else is built on it. An installation whose creation migration wrote
     * `session_id` wrote `unique(user_id, session_id)` and the session index
     * over it in the same breath, and neither is this migration to take
     * apart. The legacy shape this does reverse has no such thing: the pair
     * arrives with `make_oauth_tokens_per_session`, whose own `down()` takes it
     * back off first — a full rollback therefore reaches here with nothing left
     * standing on the column, and drops it.
     *
     * This is also simply true of the column: a driver will not drop one an
     * index still names.
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
