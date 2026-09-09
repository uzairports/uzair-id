<?php

namespace Uzairports\Uzairid\Actions;

use GuzzleHttp\Exception\RequestException;
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
     * `$revoke` is the one part of this that costs a round-trip, and it costs
     * one per login: the identity provider is told about each grant in turn,
     * and there is no telling in advance how many an account holds. Where that
     * wait is being paid by a browser — signing in under `single_session` — it
     * can be given up. The first two steps still happen, so the account is
     * signed out here either way; what is surrendered is the promise that its
     * grants stop being honored at UzAirports ID before they expire on their
     * own.
     *
     * @return int the number of logins ended
     */
    public function __invoke(int|string $userId, ?string $exceptSessionId = null, bool $revoke = true): int
    {
        $tokens = OauthToken::query()
            ->where('user_id', $userId)
            ->when($exceptSessionId !== null, fn ($query) => $query->where(
                fn ($q) => $q->whereNull('session_id')->orWhere('session_id', '!=', $exceptSessionId)
            ))
            ->get();

        $sessionIds = [];

        foreach ($tokens as $token) {
            $sessionId = $token->session_id;
            if (is_string($sessionId) && $sessionId !== '') {
                $sessionIds[] = $sessionId;
            }

            $token->delete();
        }

        $this->deleteStoredSessions($userId, $exceptSessionId, $sessionIds);

        if ($revoke) {
            foreach ($tokens as $token) {
                $this->revoke($token);
            }
        }

        return $tokens->count();
    }

    /**
     * Refuse the login locally before submitting remote revocation.
     */
    public function end(OauthToken $token): void
    {
        $token->delete();

        if ($token->session_id !== null) {
            $this->deleteStoredSessionById($token->session_id);
        }

        $this->revoke($token);
    }

    /**
     * Give a login's grant up at the identity provider, leaving the row alone.
     *
     * This is what pruning needs. The sweep deletes the row itself. The
     * store collected the session it named long before the sweep
     * reached it — so all that is left is to stop the identity provider
     * honoring a grant nobody is holding anymore.
     */
    public function surrender(OauthToken $token): void
    {
        $this->revoke($token);
    }

    /**
     * Revoke both tokens during this request after local access has ended.
     * Each call has the provider's revocation timeout. A failed access-token
     * revocation must not prevent the refresh token from being surrendered.
     *
     * A token that will not open is anything this can hand over, and the model
     * has already recorded why — so a login holding only unreadable values is
     * ended locally, and the identity provider is asked for nothing.
     */
    private function revoke(OauthToken $token): void
    {
        $accessToken = $token->readableAccessToken();
        $refreshToken = $token->readableRefreshToken();

        if ($accessToken === null && $refreshToken === null) {
            return;
        }

        try {
            /** @var UzairportsProvider $provider */
            $provider = Socialite::driver('uzairports');
        } catch (Throwable $exception) {
            $this->reportFailedRevocation($token, $exception);

            return;
        }

        if ($accessToken !== null) {
            try {
                $provider->logout($accessToken);
            } catch (Throwable $exception) {
                if (! $exception instanceof RequestException || $exception->getResponse()?->getStatusCode() !== 401) {
                    $this->reportFailedRevocation($token, $exception);
                }
            }
        }

        if ($refreshToken !== null) {
            try {
                $provider->revokeRefreshToken($refreshToken);
            } catch (Throwable $exception) {
                $this->reportFailedRevocation($token, $exception);
            }
        }
    }

    private function reportFailedRevocation(OauthToken $token, Throwable $exception): void
    {
        Log::warning('Failed to revoke an UzAirports token.', [
            'user_id' => $token->user_id,
            'exception_class' => $exception::class,
            'http_status' => $exception instanceof RequestException ? $exception->getResponse()?->getStatusCode() : null,
        ]);
    }

    private function deleteStoredSessionById(string $sessionId): void
    {
        if (config('session.driver') !== 'database') {
            return;
        }

        $connection = config('session.connection');
        $table = config('session.table', 'sessions');

        try {
            DB::connection(is_string($connection) ? $connection : null)
                ->table(is_string($table) ? $table : 'sessions')
                ->where('id', $sessionId)
                ->delete();
        } catch (Throwable $e) {
            Log::warning('Failed to delete the stored session of an UzAirports user.', [
                'exception_class' => $e::class,
            ]);
        }
    }

    /**
     * Drop the account's sessions from the session store.
     *
     * A store that cannot be reached must not cost the caller the rest of the
     * work, so a failure here is logged: the rows are gone already, and the
     * middleware refuses those sessions on their next request regardless.
     *
     * @param  array<array-key, string>  $sessionIds
     */
    private function deleteStoredSessions(int|string $userId, ?string $exceptSessionId, array $sessionIds = []): void
    {
        if (config('session.driver') !== 'database') {
            return;
        }

        $connection = config('session.connection');
        $table = config('session.table', 'sessions');

        try {
            DB::connection(is_string($connection) ? $connection : null)
                ->table(is_string($table) ? $table : 'sessions')
                ->where(function ($query) use ($userId, $sessionIds): void {
                    $query->where('user_id', $userId);
                    if (! empty($sessionIds)) {
                        $query->orWhereIn('id', $sessionIds);
                    }
                })
                ->when($exceptSessionId !== null, fn ($query) => $query->where('id', '!=', $exceptSessionId))
                ->delete();
        } catch (Throwable $e) {
            Log::warning('Failed to delete the stored sessions of an UzAirports user.', [
                'user_id' => $userId,
                'exception_class' => $e::class,
            ]);
        }
    }
}
