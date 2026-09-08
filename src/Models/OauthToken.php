<?php

namespace Uzairports\Uzairid\Models;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Prunable;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Support\Carbon;
use Illuminate\Support\Str;
use RuntimeException;

/**
 * One SSO login: the tokens it was issued and the browser session holding them.
 *
 * A user has one row per session, so the same account may be signed in on a
 * phone and a desktop at once, each with its own grant. That is how OAuth means
 * it: each browser exchanged its own authorization code, so each has its own
 * refresh token to rotate.
 *
 * @property int|string $user_id
 * @property string $access_token
 * @property string|null $refresh_token
 * @property Carbon|null $expires_at
 * @property string|null $session_id
 * @property string|null $ip_address
 * @property string|null $user_agent
 * @property Carbon $created_at
 * @property Carbon $updated_at
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
     * owner worked, and be pruned out from under them.
     *
     * Pruning runs through Laravel's `model:prune` command, which the host
     * application has to schedule for the rows to actually go.
     *
     * @return Builder<OauthToken>
     */
    public function prunable(): Builder
    {
        return $this->newQuery()->where('updated_at', '<', now()->subMinutes(self::sessionLifetime() * 2));
    }

    /**
     * Record that the login is still in use, if it has not been written lately.
     *
     * `updated_at` is what pruning reads, and nothing else writes the row
     * between refreshes — so on its own it would say when the token last
     * changed rather than when the browser was last here. This closes that gap
     * while keeping the cost to one writing per half a session lifetime, instead
     * of one on every request.
     */
    public function keepAlive(): void
    {
        $staleAfter = now()->subMinutes(max(intdiv(self::sessionLifetime(), 2), 1));

        if ($this->updated_at->greaterThan($staleAfter)) {
            return;
        }

        $this->forceFill(['updated_at' => now()])->saveQuietly();
    }

    /**
     * How long the host application keeps a session, in minutes.
     */
    private static function sessionLifetime(): int
    {
        return max((int) config('session.lifetime', 120), 1);
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
