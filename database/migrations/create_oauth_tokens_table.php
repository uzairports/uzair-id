<?php

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * The string key types `user_id` can be shaped like and constrained to.
     *
     * A `text` key is left out along with the numeric ones: MySQL will not
     * index it without a prefix length, and a column that cannot be indexed
     * cannot be referenced.
     *
     * `stringKeyColumn()` narrows to this list and `mirrorColumn()` has an arm
     * for each member, so the two are named from one place rather than kept in
     * step by hand.
     */
    private const REFERENCEABLE_TYPES = ['uuid', 'char', 'bpchar', 'varchar'];

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

            $this->defineUserIdColumn($table);

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

    /**
     * Define `user_id`, with the foreign key behind it wherever one can hold.
     *
     * An account with an integer key is named by `foreignId()`, which spells
     * the column and its constraint together.
     *
     * An account keyed by a string — a UUID, a ULID, an employee number — used
     * to get a bare `varchar(255)` and nothing else, so deleting a person left
     * their logins standing as rows pointing at an account that is gone. The
     * pruning sweep does reach them eventually, since `OauthToken::prunable()`
     * goes by `updated_at` and an abandoned row stops being touched — but not
     * promptly, and only where `model:prune` is scheduled at all.
     *
     * The constraint cannot simply be asked for, because the column has to
     * match the one it references before any driver accepts it — MySQL refuses
     * `varchar(255)` against a `char(36)` key, Postgres refuses it against a
     * `uuid`. So the users table is read and its key column is mirrored: type,
     * length, and on MySQL the collation, which is its own way to be refused
     * and need not be the same in two tables.
     *
     * Where that column cannot be read the column is written as it always was
     * and left unconstrained. Two cases reach that — the users table does not
     * exist yet, and a model whose `$keyType` says `string` over a column that
     * is nothing of the sort. Neither could be given a constraint that would
     * hold, and neither is worth failing the migration over.
     *
     * What the cascade is NOT is a way to end a login. It deletes underneath
     * Eloquent: no model events, so nothing observing logouts hears about it,
     * no `OauthToken::forgetLogin()`, and above all no grant surrendered to the
     * identity provider — the access and refresh tokens of a deleted account
     * stay live at UzAirports ID until they expire on their own. It is an
     * integrity net for rows nobody could use anyway. An application that
     * deletes users must still end their logins through `EndSessions` first.
     * This has always been how the integer branch below behaved; the string
     * branch now behaves the same way rather than leaving the rows behind.
     */
    private function defineUserIdColumn(Blueprint $table): void
    {
        $user = $this->userModel();

        if (! $user instanceof Model) {
            $table->foreignId('user_id')->constrained()->cascadeOnDelete()->cascadeOnUpdate();

            return;
        }

        // `foreignIdFor()` reads the model's own key rather than assuming the
        // conventional `id`, which `constrained($table)` would have referenced
        // whatever the model actually calls its key.
        if ($user->getKeyType() !== 'string') {
            $table->foreignIdFor($user, 'user_id')->constrained()->cascadeOnDelete()->cascadeOnUpdate();

            return;
        }

        $key = $this->stringKeyColumn($user);

        if ($key === null) {
            $table->string('user_id');

            return;
        }

        $this->mirrorColumn($table, $key);

        $table->foreign('user_id')
            ->references($user->getKeyName())
            ->on($user->getTable())
            ->cascadeOnDelete()
            ->cascadeOnUpdate();
    }

    /**
     * The configured user model, or null where the application names none.
     */
    private function userModel(): ?Model
    {
        $userModel = config('auth.providers.users.model');

        if (! is_string($userModel) || ! class_exists($userModel)) {
            return null;
        }

        $user = new $userModel;

        return $user instanceof Model ? $user : null;
    }

    /**
     * The account's key column, if it exists and is one a string may reference.
     *
     * @return array<string, mixed>|null
     */
    private function stringKeyColumn(Model $user): ?array
    {
        if (! Schema::hasTable($user->getTable())) {
            return null;
        }

        $key = array_find(
            Schema::getColumns($user->getTable()),
            fn (array $column): bool => $column['name'] === $user->getKeyName(),
        );

        if ($key === null || ! in_array($this->typeName($key), self::REFERENCEABLE_TYPES, true)) {
            return null;
        }

        return $key;
    }

    /**
     * Write `user_id` shaped like the column it is about to reference.
     *
     * The arms cover `self::REFERENCEABLE_TYPES` and nothing else, which is
     * what `stringKeyColumn()` has already narrowed the type to.
     *
     * Every driver that names a type `char` names its length beside it, so the
     * fallback width is nominal — it is a UUID's, that being what a fixed-width
     * key is in practice.
     *
     * @param  array<string, mixed>  $key
     */
    private function mirrorColumn(Blueprint $table, array $key): void
    {
        $length = $this->length($key);

        $column = match ($this->typeName($key)) {
            'uuid' => $table->uuid('user_id'),
            'char', 'bpchar' => $table->char('user_id', $length ?? 36),
            default => $table->string('user_id', $length),
        };

        $collation = $key['collation'] ?? null;

        if (is_string($collation) && $collation !== '' && $this->collationMustMatch()) {
            $column->collation($collation);
        }
    }

    /**
     * Whether the driver refuses a foreign key across differing collations.
     *
     * MySQL does — errno 3780, and two tables need not share a default. The
     * others compare the type and leave the collation out of it, and a MySQL
     * collation named on Postgres or SQLite would be refused in its own right,
     * so it is spelled only where it is read.
     */
    private function collationMustMatch(): bool
    {
        return in_array(Schema::getConnection()->getDriverName(), ['mysql', 'mariadb'], true);
    }

    /**
     * The lowercased name of a column's type, without the length beside it.
     *
     * @param  array<string, mixed>  $column
     */
    private function typeName(array $column): string
    {
        $typeName = $column['type_name'] ?? null;

        return is_string($typeName) ? strtolower($typeName) : '';
    }

    /**
     * The length a column's full type declares, where it declares one.
     *
     * Postgres writes `character varying(36)` where MySQL writes `varchar(36)`,
     * and SQLite writes `varchar` with no length at all — the number in
     * parentheses is the one part all three spell the same way.
     *
     * @param  array<string, mixed>  $column
     */
    private function length(array $column): ?int
    {
        $type = $column['type'] ?? null;

        if (is_string($type) && preg_match('/\((\d+)\)/', $type, $matches) === 1) {
            return (int) $matches[1];
        }

        return null;
    }
};
