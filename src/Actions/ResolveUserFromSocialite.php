<?php

namespace Uzairports\Uzairid\Actions;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use Laravel\Socialite\Two\User as SocialiteUser;
use RuntimeException;

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
     * The profile is written with `forceFill()` so that the host model does not
     * have to expose these columns for mass assignment.
     *
     * @throws RuntimeException when the identity provider omits the user id
     */
    public function __invoke(SocialiteUser $uzairUser): Model
    {
        $uzairId = (string) $uzairUser->getId();

        if (blank($uzairId)) {
            throw new RuntimeException('UzAirports SSO returned a user without an id.');
        }

        $email = $uzairUser->getEmail() ?: null;

        $user = $this->query()->firstWhere('uzair_id', $uzairId)
            ?? $this->findUnlinkedUserByEmail($email)
            ?? $this->newUser();

        $name = $uzairUser->getName();
        if (blank($name)) {
            $name = $user->getAttribute('name') ?: 'User';
        }

        $user->forceFill([
            'uzair_id' => $uzairId,
            'name' => $name,
            'email' => $email,
        ])->save();

        return $user;
    }

    /**
     * Find an account created before the package was installed.
     *
     * An account without an e-mail address carries no evidence of who owns it,
     * so it is never claimed this way.
     */
    private function findUnlinkedUserByEmail(?string $email): ?Model
    {
        if ($email === null || ! config('uzairports.link_by_email', true)) {
            return null;
        }

        return $this->query()->whereNull('uzair_id')->firstWhere('email', $email);
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
