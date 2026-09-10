<?php

namespace Uzairports\Uzairid\Actions;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use Laravel\Socialite\Two\User as SocialiteUser;
use RuntimeException;
use Uzairports\Uzairid\Uzair;

class ResolveUserFromSocialite
{
    /**
     * Resolve the local account behind an UzAirports identity and refresh its profile.
     *
     * Only the SSO `id` is a stable identifier: the user can change the name and
     * e-mail address at any time on the identity provider, the address may be
     * shared between accounts, and it may be missing entirely. Matching by e-mail
     * is therefore just a one-off migration path for accounts created before the
     * package was installed.
     *
     * What the identity provider leaves out is not an answer about the account.
     * The name and the e-mail address are optional on its side, and a sign-in
     * that arrives without one says nothing more than that it was not sent — so
     * the stored value stands rather than being overwritten with nothing. An
     * address that actually changed still arrives as an address, and is written.
     *
     * The profile is written with `forceFill()` so that the host model does not
     * have to expose these columns for mass assignment.
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

        $user->forceFill([
            'uzair_id' => $uzairId,
            'name' => $name,
            'email' => $email,
        ])->save();

        return $user;
    }

    /**
     * Take an account created before the package was installed, if it is still
     * there to be taken.
     *
     * Finding the account and claiming it are two statements, and an account
     * nobody has linked is exactly the kind another identity may be linking at
     * the same moment. Both would see `uzair_id` empty, both would write, and
     * the unique index cannot refuse either of them — it is one row, written
     * twice, so the second write is an ordinary update. Two people would then
     * be signed in to one local account, which is the worst outcome this action
     * has: the whole reason `uzair_id` is the only identifier trusted here is
     * that an address is not proof of who owns it.
     *
     * So the claim is made conditional on the account still being unlinked, and
     * whoever finds it already taken does not argue: an address the identity
     * provider never promised to have verified is not enough to take an account
     * from whoever got there first. The loser gets a new account, which is what
     * linking being off would have given it anyway.
     *
     * A second callback for the same identity that arrives here loses the claim
     * too, and its new account is refused by the unique index on `uzair_id` —
     * `UzairAuthController` retries once and finds the row the winner linked.
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
     * An account without an e-mail address carries no evidence of who owns it,
     * so it is never claimed this way. Neither is an address more than one
     * unclaimed account carries: the migrations drop the unique index on
     * `users.email`, so duplicates are expected, and picking one of them would
     * hand the identity whichever row the database happened to return first.
     *
     * Linking is off unless the host application turns it on, because the
     * identity provider does not promise that the address it reports was ever
     * verified, and an unverified address is enough to claim the account.
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
        $model = config('auth.providers.users.model');

        if (! is_string($model) || ! is_subclass_of($model, Model::class)) {
            throw new RuntimeException('The configured auth user model is not an Eloquent model.');
        }

        return new $model;
    }
}
