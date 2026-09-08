<?php

namespace Uzairports\Uzairid\Actions;

use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;
use Laravel\Socialite\Facades\Socialite;
use Throwable;
use Uzairports\Uzairid\Models\OauthToken;
use Uzairports\Uzairid\Socialite\UzairportsProvider;

class EndSessions
{
    /**
     * End the account's logins, optionally sparing one.
     *
     * Three things have to go for a device to actually be signed out, and each
     * covers a gap the others leave:
     *
     * - The token is revoked at UzAirports ID. Without this the device is only
     *   sent back through `login`, where the identity provider — which still
     *   holds a session for that browser — answers with a fresh authorization
     *   code and lets it straight back in;
     * - The row is deleted, so `uzair.token` refuses that session on its next
     *   request whatever the session driver is;
     * - The session itself is deleted from the store, so a device that never
     *   reaches the middleware loses its session too. Only the database driver
     *   keeps sessions somewhere this can reach.
     *
     * Pass `$exceptSessionId` to keep the browser in front of you signed in.
     *
     * @return int the number of logins ended
     */
    public function __invoke(int|string $userId, ?string $exceptSessionId = null): int
    {
        $tokens = OauthToken::query()
            ->where('user_id', $userId)
            ->when($exceptSessionId !== null, fn ($query) => $query->where(
                fn ($q) => $q->whereNull('session_id')->orWhere('session_id', '!=', $exceptSessionId)
            ))
            ->get();

        foreach ($tokens as $token) {
            $this->end($token);
        }

        $this->deleteStoredSessions($userId, $exceptSessionId);

        return $tokens->count();
    }

    /**
     * End one login: give its token up at the identity provider and drop the row.
     */
    public function end(OauthToken $token): void
    {
        $this->revoke($token);

        $token->delete();
    }

    /**
     * Give up both of the login's tokens at the identity provider.
     *
     * The access token is what `logout` hands back, and it is the only thing
     * the provider is told about there. The refresh token is surrendered
     * separately. Nothing in OAuth promises that retiring an access
     * token retires the refresh token issued with it — and one that outlives
     * the logout is a way back into the account for whoever holds a copy.
     * Where the provider offers no revocation endpoint, the second call is a
     * no-op; see `uzairports.revoke_endpoint`.
     *
     * The two are attempted independently, so a provider that refuses one still
     * hears about the other. An identity provider that cannot be reached at all
     * must not keep the user signed in here, so the row goes either way and the
     * failures are only logged.
     */
    private function revoke(OauthToken $token): void
    {
        if (blank($token->access_token) && blank($token->refresh_token)) {
            return;
        }

        try {
            /** @var UzairportsProvider $provider */
            $provider = Socialite::driver('uzairports');
        } catch (Throwable $e) {
            $this->reportFailedRevocation($token, $e);

            return;
        }

        if (filled($token->access_token)) {
            try {
                $provider->logout($token->access_token);
            } catch (Throwable $e) {
                $this->reportFailedRevocation($token, $e);
            }
        }

        if (filled($token->refresh_token)) {
            try {
                $provider->revokeRefreshToken($token->refresh_token);
            } catch (Throwable $e) {
                $this->reportFailedRevocation($token, $e);
            }
        }
    }

    private function reportFailedRevocation(OauthToken $token, Throwable $e): void
    {
        Log::warning('Failed to revoke an UzAirports token while ending a session: '.($e->getMessage() ?: $e::class), [
            'user_id' => $token->user_id,
        ]);
    }

    /**
     * Drop the account's sessions from the session store.
     *
     * A store that cannot be reached must not cost the caller the rest of the
     * work, so a failure here is logged: the rows are gone already, and the
     * middleware refuses those sessions on their next request regardless.
     */
    private function deleteStoredSessions(int|string $userId, ?string $exceptSessionId): void
    {
        if (config('session.driver') !== 'database') {
            return;
        }

        $connection = config('session.connection');
        $table = config('session.table', 'sessions');

        try {
            DB::connection(is_string($connection) ? $connection : null)
                ->table(is_string($table) ? $table : 'sessions')
                ->where('user_id', $userId)
                ->when($exceptSessionId !== null, fn ($query) => $query->where('id', '!=', $exceptSessionId))
                ->delete();
        } catch (Throwable $e) {
            Log::warning('Failed to delete the stored sessions of an UzAirports user: '.$e->getMessage(), [
                'user_id' => $userId,
            ]);
        }
    }
}
