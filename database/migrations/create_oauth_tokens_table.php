<?php

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;
use Uzairports\Uzairid\Uzair;

return new class extends Migration
{
    public string $table = 'oauth_tokens';

    /**
     * The string key types `user_id` can mirror and reference. `text` is
     * excluded because MySQL cannot index it without a prefix length.
     * `mirrorColumn()` must keep an arm for each member.
     */
    private const array REFERENCEABLE_TYPES = ['uuid', 'char', 'bpchar', 'varchar'];

    /**
     * Run the migrations.
     *
     * A row is one login, so an account may be signed in on several devices.
     * `(user_id, session_id)` is unique so a session has one row and racing
     * callbacks fail rather than duplicate. A null `expires_at` counts as
     * expired; `refresh_token` and `session_id` are optional.
     *
     * `personal_access_token_id` identifies a mobile login: unique, and
     * deliberately not a foreign key, since Sanctum is optional and a cascade
     * would end the login without `EndSessions` surrendering its grant.
     *
     * `updated_at` (pruning) and `session_id` (sign-in lookup, which cannot be
     * scoped to the account) need their own indexes because the unique pair
     * leads with `user_id`.
     */
    public function up(): void
    {
        $this->userModel();

        Schema::create($this->table, function (Blueprint $table) {
            $table->id();

            $this->defineUserIdColumn($table);

            $table->text('access_token');
            $table->text('refresh_token')->nullable();
            $table->timestamp('expires_at')->nullable();
            $table->string('session_id')->nullable();
            $table->unsignedBigInteger('personal_access_token_id')->nullable()->unique();
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
        $this->userModel();

        Schema::dropIfExists($this->table);
    }

    /**
     * Define `user_id` with a cascading foreign key wherever one can hold.
     *
     * A string key is constrained only after mirroring the referenced column's
     * type, length and (on MySQL) collation, since drivers reject mismatches.
     * When that column cannot be read (missing table, non-string column), a
     * plain unconstrained `string` is written instead.
     *
     * The cascade is an integrity net, not a way to end a login: it bypasses
     * Eloquent and surrenders no grant to the identity provider. Applications
     * must end a user's logins through `EndSessions` before deleting them.
     */
    private function defineUserIdColumn(Blueprint $table): void
    {
        $user = $this->userModel();

        // `foreignIdFor()` references the model's own key name, not a hardcoded `id`.
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
     * An instance of the configured user model.
     */
    private function userModel(): Model
    {
        $userModel = Uzair::userModel();

        return new $userModel;
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
     * Write `user_id` shaped like the column it references. The arms cover
     * exactly `self::REFERENCEABLE_TYPES`; the `char` fallback width is nominal.
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
     * Whether the driver refuses a foreign key across differing collations
     * (MySQL/MariaDB only; elsewhere the collation is not copied).
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
     * The length in parentheses in a column's full type, if any; this form is
     * consistent across drivers.
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
