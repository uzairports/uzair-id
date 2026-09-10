<?php

namespace Uzairports\Uzairid\Tests;

use Laravel\Socialite\Two\User as SocialiteUser;
use Uzairports\Uzairid\Events\UzairAuthenticated;
use Uzairports\Uzairid\Models\OauthToken;

class UzairAuthenticatedTest extends TestCase
{
    /**
     * A listener implementing `ShouldQueue` has the event serialized into the
     * queue payload — a row in `jobs`, a string in Redis, a line in whatever
     * records a failed job. The identity carried the grants the handshake had
     * just been issued, so both were written there in plain sight, beside a
     * `$token` the package takes an encrypted cast to keep out of exactly that.
     */
    public function test_the_grants_are_not_written_into_a_queue_payload(): void
    {
        $event = $this->authenticated();

        $payload = serialize($event);

        $this->assertStringNotContainsString('access_token_value', $payload);
        $this->assertStringNotContainsString('refresh_token_value', $payload);
    }

    /**
     * What is stripped is the credential and nothing else: a queued listener is
     * dispatched to do something with the identity that signed in, and it still
     * gets one.
     */
    public function test_the_identity_survives_the_payload_without_its_grants(): void
    {
        $restored = unserialize(serialize($this->authenticated()));

        $this->assertInstanceOf(UzairAuthenticated::class, $restored);

        $this->assertSame('6001', $restored->socialiteUser->getId());
        $this->assertSame('Captain Pilot', $restored->socialiteUser->getName());
        $this->assertSame('pilot@uzairports.com', $restored->socialiteUser->getEmail());
        $this->assertSame(3600, $restored->socialiteUser->expiresIn);

        $this->assertEmpty($restored->socialiteUser->token);
        $this->assertEmpty($restored->socialiteUser->refreshToken);
    }

    /**
     * The login row is the one place the package keeps a grant, and it is what
     * a queued listener needing one reads: `SerializesModels` writes the model
     * in as an identifier, so the tokens come back out of the database through
     * their casts rather than out of the payload.
     */
    public function test_a_restored_login_still_answers_with_its_grant(): void
    {
        $restored = unserialize(serialize($this->authenticated()));

        $this->assertInstanceOf(UzairAuthenticated::class, $restored);
        $this->assertInstanceOf(OauthToken::class, $restored->token);
        $this->assertSame('access_token_value', $restored->token->readableAccessToken());
    }

    /**
     * Only what leaves the process is stripped. The event belongs to the
     * request that dispatched it, and a synchronous listener running after a
     * queued one is entitled to find the identity as it was handed over.
     */
    public function test_the_dispatched_event_keeps_the_grants_it_was_built_with(): void
    {
        $event = $this->authenticated();

        serialize($event);

        $this->assertSame('access_token_value', $event->socialiteUser->token);
        $this->assertSame('refresh_token_value', $event->socialiteUser->refreshToken);
    }

    /**
     * The event as the callback dispatches it.
     *
     * The identity is built the way `UzairportsProvider` builds one — the raw
     * payload is the userinfo response, which carries the profile and no
     * credential — rather than through `SocialiteUser::fake()`, which files
     * whatever it is handed under the raw payload as well, tokens included.
     */
    private function authenticated(): UzairAuthenticated
    {
        $user = TestUser::create(['uzair_id' => '6001', 'name' => 'Captain Pilot']);

        $token = $user->tokens()->create([
            'access_token' => 'access_token_value',
            'refresh_token' => 'refresh_token_value',
            'expires_at' => now()->addHour(),
            'session_id' => 'the-browsers-session',
        ]);

        $profile = [
            'id' => '6001',
            'name' => 'Captain Pilot',
            'email' => 'pilot@uzairports.com',
            'avatar' => 'https://my.uzairports.test/avatar.jpg',
        ];

        $identity = (new SocialiteUser)
            ->setRaw($profile)
            ->map($profile)
            ->setToken('access_token_value')
            ->setRefreshToken('refresh_token_value')
            ->setExpiresIn(3600);

        return new UzairAuthenticated($user, $identity, $token);
    }
}
