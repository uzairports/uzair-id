<?php

namespace Uzairports\Uzairid\Actions;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Log;
use Laravel\Socialite\Two\User as SocialiteUser;
use RuntimeException;
use Uzairports\Uzairid\Uzair;

class ResolveUserFromSocialite
{
    /**
     * Resolve the local account behind an UzAirports identity and refresh its profile.
     *
     * Only the SSO `id` is a stable identifier; the e-mail address can change,
     * be shared or be missing. Matching by e-mail is only a migration path for
     * accounts created before the package was installed.
     *
     * A name or e-mail the provider omits keeps the stored value. `forceFill()`
     * avoids requiring the host model to make these columns mass assignable.
     *
     * @throws RuntimeException when the identity provider omits the user id
     */
    public function __invoke(SocialiteUser $uzairUser): Model
    {
        $resolver = Uzair::getUserResolver();
        if ($resolver !== null) {
            $resolved = $resolver($uzairUser);
            if ($resolved instanceof Model) {
                return $resolved;
            }
        }

        $uzairId = (string) $uzairUser->getId();

        if (blank($uzairId)) {
            throw new RuntimeException('UzAirports SSO returned a user without an id.');
        }

        $reportedEmail = $uzairUser->getEmail() ?: null;

        $user = $this->query()->firstWhere('uzair_id', $uzairId)
            ?? $this->claimUnlinkedUserByEmail($reportedEmail, $uzairId)
            ?? $this->newUser();

        $name = $uzairUser->getName();
        if (blank($name)) {
            $name = $user->getAttribute('name') ?: 'User';
        }

        $email = $reportedEmail ?? $user->getAttribute('email');

        $saved = $user->forceFill([
            'uzair_id' => $uzairId,
            'name' => $name,
            'email' => $email,
        ])->save();

        if (! $saved) {
            $this->reportRefusedProfile($user);
        }

        return $user;
    }

    /**
     * Log a profile write refused by a `saving` listener and restore the stored
     * attributes.
     *
     * The sign-in proceeds: the account is still the right one, only the
     * profile is stale. Attributes are reset so `Auth::login()` and its
     * listeners do not see unsaved values. A refused insert is handled by
     * `StoreAccount`, which rejects non-existent models.
     */
    private function reportRefusedProfile(Model $user): void
    {
        Log::warning('A model listener refused the write that refreshes an UzAirports profile, so the stored one stands.', [
            'user_id' => $user->getKey(),
            'account_exists' => $user->exists,
        ]);

        if ($user->exists) {
            $user->setRawAttributes($user->getRawOriginal(), sync: true);
        }
    }

    /**
     * Link a pre-existing account by e-mail, only if it is still unlinked.
     *
     * Finding and claiming are separate statements, and the unique index on
     * `uzair_id` cannot stop two identities updating the same row. The update
     * is therefore conditional on `uzair_id` being null; a loser gets a new
     * account rather than sharing one. A concurrent callback for the same
     * identity hits the unique index, and `StoreAccount` retries once.
     */
    private function claimUnlinkedUserByEmail(?string $email, string $uzairId): ?Model
    {
        $candidate = $this->findUnlinkedUserByEmail($email);

        if ($candidate === null) {
            return null;
        }

        $claimed = $this->query()
            ->whereKey($candidate->getKey())
            ->whereNull('uzair_id')
            ->update(['uzair_id' => $uzairId]);

        return $claimed === 1 ? $candidate : null;
    }

    /**
     * Find an account created before the package was installed.
     *
     * Requires `link_by_email` (off by default, since the provider does not
     * guarantee verified addresses), a non-empty e-mail, and exactly one
     * unlinked match; `users.email` is not unique, so duplicates are ambiguous.
     */
    private function findUnlinkedUserByEmail(?string $email): ?Model
    {
        if ($email === null || ! config('uzairports.link_by_email', false)) {
            return null;
        }

        $candidates = $this->query()
            ->whereNull('uzair_id')
            ->where('email', $email)
            ->limit(2)
            ->get();

        if ($candidates->count() !== 1) {
            return null;
        }

        return $candidates->first();
    }

    /**
     * @return Builder<Model>
     */
    private function query(): Builder
    {
        return $this->newUser()->newQuery();
    }

    /**
     * Build an empty instance of the model the host application authenticates.
     */
    private function newUser(): Model
    {
        $model = Uzair::userModel();

        return new $model;
    }
}
