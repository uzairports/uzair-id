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
     * their logins standing as rows pointing at an account that is gone. They
     * are never read again and never cleaned up either: `OauthToken::prunable()`
     * sweeps by `updated_at`, not by whether the owner still exists.
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
     */
    private function defineUserIdColumn(Blueprint $table): void
    {
        $user = $this->userModel();

        if (! $user instanceof Model) {
            $table->foreignId('user_id')->constrained()->cascadeOnDelete()->cascadeOnUpdate();

            return;
        }

        if ($user->getKeyType() !== 'string') {
            $table->foreignId('user_id')->constrained($user->getTable())->cascadeOnDelete()->cascadeOnUpdate();

            return;
        }

        $key = $this->stringKeyColumn($user);

        if ($key === null) {
            $table->string('user_id');

            return;
        }

        $this->mirrorColumn($table, 'user_id', $key);

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
     * A `text` key is left out along with the numeric ones: MySQL will not
     * index it without a prefix length, and a column that cannot be indexed
     * cannot be referenced.
     *
     * @return array<string, mixed>|null
     */
    private function stringKeyColumn(Model $user): ?array
    {
        if (! Schema::hasTable($user->getTable())) {
            return null;
        }

        foreach (Schema::getColumns($user->getTable()) as $column) {
            if (($column['name'] ?? null) !== $user->getKeyName()) {
                continue;
            }

            return in_array($this->typeName($column), ['uuid', 'char', 'bpchar', 'varchar'], true)
                ? $column
                : null;
        }

        return null;
    }

    /**
     * Write a column shaped like the one it is about to reference.
     *
     * @param  array<string, mixed>  $key
     */
    private function mirrorColumn(Blueprint $table, string $name, array $key): void
    {
        $length = $this->length($key);

        $column = match ($this->typeName($key)) {
            'uuid' => $table->uuid($name),
            'char', 'bpchar' => $table->char($name, $length ?? 36),
            default => $length === null ? $table->string($name) : $table->string($name, $length),
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
