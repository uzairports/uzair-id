<?php

namespace Uzairports\Uzairid\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Support\Carbon;
use RuntimeException;

/**
 * @property int $user_id
 * @property string $access_token
 * @property string $refresh_token
 * @property int $expires_in
 * @property Carbon|null $expires_at
 */
class OauthToken extends Model
{
    protected $fillable = [
        'access_token',
        'refresh_token',
        'expires_in',
        'expires_at',
    ];

    protected $hidden = [
        'access_token',
        'refresh_token',
    ];

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'expires_in' => 'integer',
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
}
