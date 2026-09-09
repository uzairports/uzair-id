<?php

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Run the migrations.
     *
     * `expires_at` is the moment the access token stops being accepted, which is
     * what the refresh middleware reads. Null expiry is treated as expired,
     * so a token stored without one is renewed on the owner's next request.
     *
     * `refresh_token` is nullable because the identity provider is not obliged
     * to issue one; without it the session simply ends when the access token
     * does, and the user is sent back through the SSO flow.
     *
     * A row is one login, identified by the browser session that made it, so
     * the same account can be signed in on several devices at once — each with
     * its own grant, which is how OAuth means it. `(user_id, session_id)` is
     * unique so that one session cannot end up with two rows nobody can tell
     * apart, and so that two callbacks racing over the same session leave the
     * loser with a failed insert to retry.
     *
     * `session_id` is nullable because a token can be issued outside a session
     * — an API client, a console command.
     *
     * `ip_address` and `user_agent` are what a person recognizes their own
     * device by when they are shown the list of their logins.
     *
     * Two columns are indexed on their own, because they are the ones the
     * package reads without a `user_id` beside them — and the unique pair,
     * whose leading column is `user_id`, cannot serve a query that does not
     * name the account:
     *
     * - `updated_at`, which `OauthToken::prunable()` sweeps the whole table by;
     * - `session_id`, which the callback looks a login up by when the browser
     *   in front of it signs in again. The row it is after may belong to
     *   another account — that is the whole point of the lookup — so the query
     *   cannot be scoped, and without the index every sign-in reads the table
     *   end to end.
     *
     * Every other query names the account, and the unique pair covers those.
     */
    public function up(): void
    {
        Schema::create('oauth_tokens', function (Blueprint $table) {
            $table->id();

            $userModel = config('auth.providers.users.model');
            if (is_string($userModel) && class_exists($userModel)) {
                $user = new $userModel;
                if ($user instanceof Model) {
                    if ($user->getKeyType() === 'string') {
                        $table->string('user_id');
                    } else {
                        $table->foreignId('user_id')->constrained($user->getTable())->cascadeOnDelete()->cascadeOnUpdate();
                    }
                } else {
                    $table->foreignId('user_id')->constrained()->cascadeOnDelete()->cascadeOnUpdate();
                }
            } else {
                $table->foreignId('user_id')->constrained()->cascadeOnDelete()->cascadeOnUpdate();
            }

            $table->text('access_token');
            $table->text('refresh_token')->nullable();
            $table->timestamp('expires_at')->nullable();
            $table->string('session_id')->nullable();
            $table->string('ip_address', 45)->nullable();
            $table->text('user_agent')->nullable();
            $table->timestamps();

            $table->unique(['user_id', 'session_id']);
            $table->index('updated_at');
            $table->index('session_id');
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('oauth_tokens');
    }
};
