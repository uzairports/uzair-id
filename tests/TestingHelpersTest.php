<?php

namespace Uzairports\Uzairid\Tests;

use RuntimeException;
use Uzairports\Uzairid\Models\OauthToken;
use Uzairports\Uzairid\Testing\UzairFake;

class TestingHelpersTest extends TestCase
{
    public function test_fake_user_creates_model_with_defaults(): void
    {
        $user = UzairFake::user();

        $this->assertInstanceOf(TestUser::class, $user);
        $this->assertNotEmpty($user->getAttribute('uzair_id'));
        $this->assertSame('Fake User', $user->getAttribute('name'));
        $this->assertModelExists($user);
    }

    public function test_fake_user_with_custom_attributes(): void
    {
        $user = UzairFake::user([
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
        $user = UzairFake::user();
        $token = UzairFake::login($user);

        $this->assertInstanceOf(OauthToken::class, $token);
        $this->assertSame($user->getKey(), $token->user_id);
        $this->assertNotEmpty($token->session_id);
        $this->assertSame('fake-access-token', $token->access_token);
        $this->assertFalse($token->hasExpired());
    }

    /**
     * A fake login is a row `uzair.token` accepts; written in production it
     * would be a sign-in for whoever reached the call.
     */
    public function test_fakes_refuse_to_write_outside_the_testing_environment(): void
    {
        $user = UzairFake::user();

        app()->detectEnvironment(fn (): string => 'production');

        try {
            UzairFake::login($user);
            $this->fail('A fake login was written outside the testing environment.');
        } catch (RuntimeException) {
            $this->assertSame(0, OauthToken::query()->count());
        }

        $this->expectException(RuntimeException::class);

        UzairFake::user();
    }
}
