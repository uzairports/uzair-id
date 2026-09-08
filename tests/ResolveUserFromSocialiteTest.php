<?php

namespace Uzairports\Uzairid\Tests;

use Laravel\Socialite\Two\User as SocialiteUser;
use RuntimeException;
use Uzairports\Uzairid\Actions\ResolveUserFromSocialite;

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

        $this->assertSame('2001', $user->uzair_id);
        $this->assertSame('Agent Smith', $user->name);
        $this->assertSame('smith@uzairports.com', $user->email);
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

        $this->assertSame('Preserved Name', $resolved->name);
    }
}
