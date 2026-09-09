<?php

namespace Uzairports\Uzairid\Models;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Prunable;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Str;
use RuntimeException;
use Throwable;
use Uzairports\Uzairid\Actions\EndSessions;

/**
 * One SSO login: the tokens it was issued and the browser session holding them.
 *
 * A user has one row per session, so the same account may be signed in on a
 * phone and a desktop at once, each with its own grant. That is how OAuth means
 * it: each browser exchanged its own authorization code, so each has its own
 * refresh token to rotate.
 *
 * @property int $id
 * @property int|string $user_id
 * @property string $access_token
 * @property string|null $refresh_token
 * @property Carbon|null $expires_at
 * @property string|null $session_id
 * @property string|null $ip_address
 * @property string|null $user_agent
 * @property Carbon|null $created_at
 * @property Carbon|null $updated_at
 */
class OauthToken extends Model
{
    use Prunable;

    protected $fillable = [
        'access_token',
        'refresh_token',
        'expires_at',
        'session_id',
        'ip_address',
        'user_agent',
    ];

    protected $hidden = [
        'access_token',
        'refresh_token',
        'session_id',
    ];

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'access_token' => 'encrypted',
            'refresh_token' => 'encrypted',
            'expires_at' => 'datetime',
        ];
    }

    /**
     * The access token to this login was issued, or null if it will not open.
     */
    public function readableAccessToken(): ?string
    {
        return $this->readable('access_token');
    }

    /**
     * The refresh token this login was issued, or null if it will not open.
     */
    public function readableRefreshToken(): ?string
    {
        return $this->readable('refresh_token');
    }

    /**
     * Read one of the token columns back, answering null where it will not open.
     *
     * Both columns are `encrypted` casts, so a value written under a key the
     * application no longer holds — a rotated `APP_KEY` with no
     * `APP_PREVIOUS_KEYS` behind it, a dump restored into another environment —
     * raises a decryption failure from wherever the property is read. Left to
     * itself that is a 500 on every request the login touches, including the
     * ones that would have ended it: the grant can neither be spent nor given
     * up, and the account holding it has no way out but a support ticket.
     *
     * Null says the same thing to every caller — there is nothing here that can
     * be spent — so the login is dropped locally, and its owner signs in again,
     * which is what happens to a login whose grant is refused anyway.
     *
     * A column that is merely empty answers null too and says nothing worth
     * recording. The row carrying a value nobody can open is the one worth a
     * line, because it is a key that went missing, not a token that was never
     * issued.
     */
    private function readable(string $attribute): ?string
    {
        try {
            $value = $this->getAttribute($attribute);
        } catch (Throwable $exception) {
            Log::warning('An UzAirports token cannot be read back.', [
                'user_id' => $this->user_id,
                'attribute' => $attribute,
                'exception_class' => $exception::class,
            ]);

            return null;
        }

        return is_string($value) && filled($value) ? $value : null;
    }

    /**
     * @return BelongsTo<Model, $this>
     */
    public function user(): BelongsTo
    {
        $model = config('auth.providers.users.model');

        if (! is_string($model) || ! is_subclass_of($model, Model::class)) {
            throw new RuntimeException('The configured [auth.providers.users.model] is not an Eloquent model.');
        }

        return $this->belongsTo($model);
    }

    /**
     * The rows whose session the store has long since collected.
     *
     * A browser that is simply closed leaves its row behind: nothing signs it
     * out, and the session it names expires quietly in the session store. Twice
     * the session lifetime after the row was last used, whatever it names is
     * gone, and so is any use for the row.
     *
     * What makes that safe is `keepAlive()`: the row is written again while its
     * browser is still making requests, so `updated_at` means "last seen" and
     * not merely "last refreshed". Without it a login whose access token
     * outlives the window — an identity provider handing out an eight-hour
     * token against a two-hour session lifetime — would go untouched while its
     * owner worked and be pruned out from under them.
     *
     * Pruning runs through Laravel's `model:prune` command, which the host
     * application has to schedule for the rows to actually go.
     *
     * A row carrying no `updated_at` is swept on sight. `timestamps()` leaves
     * the column nullable, so a row written around Eloquent — a seeder, a data
     * migration, an import — can arrive without one, and null answers no
     * comparison: matched by `<` alone such a row is not merely kept, it is
     * kept for good, because nothing but `keepAlive()` on a request it may
     * never see would ever give it a date to be measured by.
     *
     * @return Builder<OauthToken>
     */
    public function prunable(): Builder
    {
        return $this->newQuery()->where(
            fn (Builder $query) => $query
                ->where('updated_at', '<', now()->subMinutes(self::sessionLifetime() * 2))
                ->orWhereNull('updated_at')
        );
    }

    /**
     * Give the login's grant up before the row goes.
     *
     * Deleting the row says nothing to UzAirports ID: the refresh token it
     * held keeps working until the identity provider retires it on its own,
     * and whoever holds a copy of it has a way into the account long after the
     * browser that earned it stopped coming back. Every other way a login ends
     * surrenders the grant; the sweep is the one that would not have.
     *
     * A provider that refuses is logged and not raised. The row goes either
     * way: it names a session the store has already collected, so leaving it
     * behind would only have it swept again tomorrow.
     *
     * Each row costs the revocation calls the provider offers, in a command
     * that may be sweeping thousands of them. Where that backlog is real and
     * the grants expire on their own, `uzairports.revoke_on_prune` turns the
     * calls off and leaves the sweep to delete rows and nothing more.
     */
    protected function pruning(): void
    {
        if (! config('uzairports.revoke_on_prune', true)) {
            return;
        }

        app(EndSessions::class)->surrender($this);
    }

    /**
     * Record that the login is still in use, if it has not been written lately.
     *
     * `updated_at` is what pruning reads, and nothing else writes the row
     * between refreshes — so on its own it would say when the token last
     * changed rather than when the browser was last here. This closes that gap
     * while keeping the cost to one writing per half a session lifetime, instead
     * of one on every request.
     *
     * The column is nullable, and a row written around Eloquent — a raw insert,
     * an import from an earlier version of the package — arrives with nothing
     * in it. Such a row is not merely unreadable here: `prunable()` compares
     * against `updated_at`, and null answers no comparison, so it would never
     * be collected either. It is stamped as seen now, which both answers the
     * question and puts the row back in reach of pruning.
     */
    public function keepAlive(): void
    {
        $staleAfter = now()->subMinutes(max(intdiv(self::sessionLifetime(), 2), 1));

        if ($this->updated_at !== null && $this->updated_at->greaterThan($staleAfter)) {
            return;
        }

        $this->forceFill(['updated_at' => now()])->saveQuietly();
    }

    /**
     * How long the host application keeps a session, in minutes.
     *
     * A lifetime that is not a number is a misconfiguration, and casting one
     * would read as zero — pruning every login on the next sweep. The default
     * stands instead.
     */
    private static function sessionLifetime(): int
    {
        $lifetime = config('session.lifetime', 120);

        return max(is_numeric($lifetime) ? (int) $lifetime : 120, 1);
    }

    /**
     * Determine whether the access token has already expired.
     *
     * Tokens stored without expiry are treated as expired so that they are
     * refreshed once and gain a known lifetime.
     */
    public function hasExpired(): bool
    {
        return $this->expiresWithin(0);
    }

    /**
     * Determine whether the access token expires within the given number of seconds.
     */
    public function expiresWithin(int $seconds): bool
    {
        if ($this->expires_at === null) {
            return true;
        }

        return $this->expires_at->lessThanOrEqualTo(now()->addSeconds($seconds));
    }

    /**
     * A short name for the device this login is running on.
     *
     * It is a guess read off the user agent, which is a string the browser is
     * free to make up: good enough for a person to recognize their own phone in
     * a list, never good enough to decide anything on.
     */
    public function deviceLabel(): string
    {
        $agent = (string) $this->user_agent;

        if ($agent === '') {
            return __('uzairid::messages.unknown_device');
        }

        $browsers = ['Edg' => 'Edge', 'OPR' => 'Opera', 'YaBrowser' => 'Yandex', 'Firefox' => 'Firefox', 'Chrome' => 'Chrome', 'Safari' => 'Safari'];
        $platforms = ['Android' => 'Android', 'iPhone' => 'iPhone', 'iPad' => 'iPad', 'Windows' => 'Windows', 'Macintosh' => 'macOS', 'Linux' => 'Linux'];

        $browser = $this->firstMatch($agent, $browsers);
        $platform = $this->firstMatch($agent, $platforms);

        if ($browser === null && $platform === null) {
            return Str::limit($agent, 40);
        }

        return trim(($browser ?? '').' — '.($platform ?? ''), ' —');
    }

    /**
     * @param  array<string, string>  $needles
     */
    private function firstMatch(string $agent, array $needles): ?string
    {
        foreach ($needles as $needle => $label) {
            if (str_contains($agent, $needle)) {
                return $label;
            }
        }

        return null;
    }
}
