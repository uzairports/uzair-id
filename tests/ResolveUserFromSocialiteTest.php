<?php

namespace Uzairports\Uzairid\Tests;

use Illuminate\Support\Facades\Log;
use Laravel\Socialite\Two\User as SocialiteUser;
use RuntimeException;
use Uzairports\Uzairid\Actions\ResolveUserFromSocialite;
use Uzairports\Uzairid\Uzair;

class ResolveUserFromSocialiteTest extends TestCase
{
    public function test_resolves_new_user(): void
    {
        $socialiteUser = SocialiteUser::fake([
            'id' => '2001',
            'name' => 'Agent Smith',
            'email' => 'smith@uzairports.com',
        ]);

        $resolver = new ResolveUserFromSocialite;
        $user = $resolver($socialiteUser);

        $this->assertSame('2001', $user->getAttribute('uzair_id'));
        $this->assertSame('Agent Smith', $user->getAttribute('name'));
        $this->assertSame('smith@uzairports.com', $user->getAttribute('email'));
    }

    public function test_throws_exception_when_id_is_missing(): void
    {
        $this->expectException(RuntimeException::class);

        $socialiteUser = SocialiteUser::fake([
            'id' => null,
            'name' => 'No ID',
        ]);

        $resolver = new ResolveUserFromSocialite;
        $resolver($socialiteUser);
    }

    public function test_a_legacy_account_is_not_claimed_by_email_unless_linking_is_turned_on(): void
    {
        $legacy = TestUser::create([
            'uzair_id' => null,
            'name' => 'Legacy',
            'email' => 'legacy@uzairports.com',
        ]);

        $resolved = (new ResolveUserFromSocialite)(SocialiteUser::fake([
            'id' => '2010',
            'name' => 'Fresh Identity',
            'email' => 'legacy@uzairports.com',
        ]));

        $this->assertNotSame($legacy->getKey(), $resolved->getKey());
        $this->assertNull($legacy->refresh()->uzair_id);
        $this->assertSame(2, TestUser::query()->count());
    }

    public function test_a_legacy_account_is_claimed_by_email_when_linking_is_turned_on(): void
    {
        config(['uzairports.link_by_email' => true]);

        $legacy = TestUser::create([
            'uzair_id' => null,
            'name' => 'Legacy',
            'email' => 'legacy@uzairports.com',
        ]);

        $resolved = (new ResolveUserFromSocialite)(SocialiteUser::fake([
            'id' => '2011',
            'name' => 'Legacy',
            'email' => 'legacy@uzairports.com',
        ]));

        $this->assertSame($legacy->getKey(), $resolved->getKey());
        $this->assertSame('2011', $legacy->refresh()->uzair_id);
        $this->assertSame(1, TestUser::query()->count());
    }

    /**
     * Finding the unlinked account and claiming it are two statements, and
     * another identity may link it in between. Both used to write the same row
     * — no unique violation, because it is one row updated twice — and two
     * people ended up signed in to one local account.
     *
     * The listener stands in for that other callback: it links the row the
     * moment this one has read it, which is exactly the window being closed.
     */
    public function test_an_account_linked_by_somebody_else_in_the_meantime_is_not_taken(): void
    {
        config(['uzairports.link_by_email' => true]);

        $legacy = TestUser::create([
            'uzair_id' => null,
            'name' => 'Legacy',
            'email' => 'legacy@uzairports.com',
        ]);

        $raced = false;

        TestUser::retrieved(function (TestUser $candidate) use (&$raced): void {
            if ($raced || $candidate->uzair_id !== null) {
                return;
            }

            $raced = true;

            TestUser::query()->whereKey($candidate->getKey())->update(['uzair_id' => 'the-identity-that-got-there-first']);
        });

        try {
            $resolved = (new ResolveUserFromSocialite)(SocialiteUser::fake([
                'id' => '2013',
                'name' => 'Late',
                'email' => 'legacy@uzairports.com',
            ]));
        } finally {
            TestUser::flushEventListeners();
        }

        $this->assertTrue($raced);
        $this->assertNotSame($legacy->getKey(), $resolved->getKey());
        $this->assertSame('the-identity-that-got-there-first', $legacy->refresh()->uzair_id);
        $this->assertSame('2013', $resolved->getAttribute('uzair_id'));
        $this->assertSame(2, TestUser::query()->count());
    }

    public function test_an_address_more_than_one_unclaimed_account_carries_links_to_neither(): void
    {
        config(['uzairports.link_by_email' => true]);

        $first = TestUser::create(['uzair_id' => null, 'name' => 'First', 'email' => 'shared@uzairports.com']);
        $second = TestUser::create(['uzair_id' => null, 'name' => 'Second', 'email' => 'shared@uzairports.com']);

        $resolved = (new ResolveUserFromSocialite)(SocialiteUser::fake([
            'id' => '2012',
            'name' => 'Ambiguous',
            'email' => 'shared@uzairports.com',
        ]));

        $this->assertNull($first->refresh()->uzair_id);
        $this->assertNull($second->refresh()->uzair_id);
        $this->assertSame('2012', $resolved->getAttribute('uzair_id'));
        $this->assertSame(3, TestUser::query()->count());
    }

    /**
     * `save()` answers false rather than raising when a listener refuses the
     * write, and dropping that answer left the caller holding a model whose
     * name this request did not write and the next one will not find.
     *
     * The sign-in is not refused over it. The account is the right one either
     * way, and an application whose listener declines a profile write is asking
     * for the stored profile to stand, not for nobody to be able to sign in.
     */
    public function test_a_refused_profile_write_leaves_the_stored_profile_standing(): void
    {
        $user = TestUser::create([
            'uzair_id' => '2014',
            'name' => 'Before',
            'email' => 'before@uzairports.com',
        ]);

        Log::shouldReceive('warning')
            ->once()
            ->withArgs(fn (string $message, array $context): bool => $context['user_id'] === $user->getKey());

        TestUser::saving(fn (): bool => false);

        try {
            $resolved = (new ResolveUserFromSocialite)(SocialiteUser::fake([
                'id' => '2014',
                'name' => 'After',
                'email' => 'after@uzairports.com',
            ]));
        } finally {
            TestUser::flushEventListeners();
        }

        $this->assertSame($user->getKey(), $resolved->getKey());

        // What the caller is handed matches what is stored, rather than the
        // values the write was refused.
        $this->assertSame('Before', $resolved->getAttribute('name'));
        $this->assertSame('before@uzairports.com', $resolved->getAttribute('email'));

        $stored = $user->refresh();
        $this->assertSame('Before', $stored->name);
        $this->assertSame('before@uzairports.com', $stored->email);
    }

    public function test_preserves_name_when_socialite_returns_blank(): void
    {
        $user = TestUser::create([
            'uzair_id' => '2002',
            'name' => 'Preserved Name',
            'email' => 'agent@uzairports.com',
        ]);

        $socialiteUser = SocialiteUser::fake([
            'id' => '2002',
            'name' => '',
            'email' => 'agent@uzairports.com',
        ]);

        $resolver = new ResolveUserFromSocialite;
        $resolved = $resolver($socialiteUser);

        $this->assertSame('Preserved Name', $resolved->getAttribute('name'));
    }

    /**
     * An address the identity provider did not send is not an address it
     * withdrew: it is optional on its side, and the sign-in says nothing about
     * the one already on file. It used to be overwritten with null.
     */
    public function test_preserves_the_stored_email_when_socialite_returns_none(): void
    {
        TestUser::create([
            'uzair_id' => '2003',
            'name' => 'Known Address',
            'email' => 'known@uzairports.com',
        ]);

        $socialiteUser = SocialiteUser::fake([
            'id' => '2003',
            'name' => 'Known Address',
            'email' => '',
        ]);

        $resolver = new ResolveUserFromSocialite;
        $resolved = $resolver($socialiteUser);

        $this->assertSame('known@uzairports.com', $resolved->getAttribute('email'));
    }

    public function test_an_address_that_changed_on_the_identity_provider_is_written(): void
    {
        TestUser::create([
            'uzair_id' => '2004',
            'name' => 'Moved Address',
            'email' => 'old@uzairports.com',
        ]);

        $socialiteUser = SocialiteUser::fake([
            'id' => '2004',
            'name' => 'Moved Address',
            'email' => 'new@uzairports.com',
        ]);

        $resolver = new ResolveUserFromSocialite;
        $resolved = $resolver($socialiteUser);

        $this->assertSame('new@uzairports.com', $resolved->getAttribute('email'));
    }

    public function test_custom_user_resolver_callback_is_honored(): void
    {
        $customUser = TestUser::create([
            'uzair_id' => '9999',
            'name' => 'Custom User',
            'email' => 'custom@uzairports.com',
        ]);

        Uzair::resolveUserUsing(fn ($socialite) => $customUser);

        try {
            $resolver = new ResolveUserFromSocialite;
            $resolved = $resolver(SocialiteUser::fake(['id' => '9999']));

            $this->assertSame($customUser->getKey(), $resolved->getKey());
            $this->assertSame('Custom User', $resolved->getAttribute('name'));
        } finally {
            Uzair::resolveUserUsing(null);
        }
    }
}
