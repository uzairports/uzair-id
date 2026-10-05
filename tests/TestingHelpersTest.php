<?php

namespace Uzairports\Uzairid\Tests;

use Uzairports\Uzairid\Models\OauthToken;
use Uzairports\Uzairid\Uzair;

class TestingHelpersTest extends TestCase
{
    public function test_fake_user_creates_model_with_defaults(): void
    {
        $user = Uzair::fakeUser();

        $this->assertInstanceOf(TestUser::class, $user);
        $this->assertNotEmpty($user->getAttribute('uzair_id'));
        $this->assertSame('Fake User', $user->getAttribute('name'));
        $this->assertModelExists($user);
    }

    public function test_fake_user_with_custom_attributes(): void
    {
        $user = Uzair::fakeUser([
            'uzair_id' => 'custom-fake-id',
            'name' => 'Custom Fake',
            'email' => 'custom@fake.test',
        ]);

        $this->assertSame('custom-fake-id', $user->getAttribute('uzair_id'));
        $this->assertSame('Custom Fake', $user->getAttribute('name'));
        $this->assertSame('custom@fake.test', $user->getAttribute('email'));
    }

    public function test_fake_login_creates_oauth_token(): void
    {
        $user = Uzair::fakeUser();
        $token = Uzair::fakeLogin($user);

        $this->assertInstanceOf(OauthToken::class, $token);
        $this->assertSame($user->getKey(), $token->user_id);
        $this->assertNotEmpty($token->session_id);
        $this->assertSame('fake-access-token', $token->access_token);
        $this->assertFalse($token->hasExpired());
    }
}
