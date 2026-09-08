<?php

namespace Uzairports\Uzairid\Tests;

use Illuminate\Support\Facades\DB;

class OauthTokenTest extends TestCase
{
    public function test_tokens_are_encrypted_in_database(): void
    {
        $user = TestUser::create([
            'uzair_id' => '1001',
            'name' => 'John Doe',
            'email' => 'john@uzairports.com',
        ]);

        $token = $user->token()->create([
            'access_token' => 'plain_access_secret',
            'refresh_token' => 'plain_refresh_secret',
            'expires_at' => now()->addHour(),
        ]);

        $this->assertSame('plain_access_secret', $token->access_token);
        $this->assertSame('plain_refresh_secret', $token->refresh_token);

        // Fetch the raw attribute directly from PDO / DB
        $raw = DB::table('oauth_tokens')->where('id', $token->id)->first();

        $this->assertNotSame('plain_access_secret', $raw->access_token);
        $this->assertNotSame('plain_refresh_secret', $raw->refresh_token);
    }

    public function test_has_expired_and_expires_within(): void
    {
        $user = TestUser::create(['uzair_id' => '1002']);

        $token = $user->token()->create([
            'access_token' => 'test',
            'expires_at' => now()->addSeconds(30),
        ]);

        $this->assertFalse($token->hasExpired());
        $this->assertTrue($token->expiresWithin(60));
        $this->assertFalse($token->expiresWithin(10));
    }
}
