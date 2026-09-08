<?php

namespace Uzairports\Uzairid\Tests;

use Illuminate\Http\Request;
use Uzairports\Uzairid\Socialite\UzairportsProvider;

class UzairportsProviderTest extends TestCase
{
    public function test_provider_generates_auth_url(): void
    {
        $request = Request::create('/');
        $provider = new UzairportsProvider($request, 'test-client', 'test-secret', 'https://app.test/callback');

        $redirectResponse = $provider->stateless()->redirect();
        $targetUrl = $redirectResponse->getTargetUrl();

        $this->assertStringStartsWith('https://my.uzairports.com/oauth/authorize', $targetUrl);
        $this->assertStringContainsString('client_id=test-client', $targetUrl);
        $this->assertStringContainsString('redirect_uri='.urlencode('https://app.test/callback'), $targetUrl);
    }

    public function test_custom_host_can_be_configured(): void
    {
        $request = Request::create('/');
        $provider = new UzairportsProvider(
            $request,
            'test-client',
            'test-secret',
            'https://app.test/callback'
        );
        $provider->setHost('https://staging.uzairports.com');

        $this->assertSame('https://staging.uzairports.com', $provider->getHost());
    }
}
