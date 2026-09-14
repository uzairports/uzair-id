<?php

namespace Uzairports\Uzairid\Socialite;

use GuzzleHttp\Exception\GuzzleException;
use GuzzleHttp\RequestOptions;
use Laravel\Socialite\Two\AbstractProvider;
use Laravel\Socialite\Two\ProviderInterface;
use Laravel\Socialite\Two\User;

class UzairportsProvider extends AbstractProvider implements ProviderInterface
{
    protected string $host = 'https://my.uzairports.com';

    protected $scopes = [];

    /**
     * OAuth 2.0 requires the requested scopes to be separated by a space,
     * whereas Socialite separates them by a comma by default.
     */
    protected $scopeSeparator = ' ';

    /**
     * The base address every OAuth and API call is built on.
     *
     * Set from `services.uzairports.host` so that an application can point the
     * driver at a staging instance of UzAirports ID without touching the code.
     */
    public function setHost(string $host): static
    {
        $this->host = rtrim(trim($host), '/');

        return $this;
    }

    protected function getAuthUrl($state): string
    {
        return $this->buildAuthUrlFromBase($this->host.'/oauth/authorize', $state);
    }

    protected function getTokenUrl(): string
    {
        return $this->host.'/oauth/token';
    }

    /**
     * @throws GuzzleException
     */
    protected function getUserByToken($token)
    {
        $response = $this->getHttpClient()->get(
            $this->host.'/api/user', $this->getRequestOptions($token)
        );

        return json_decode($response->getBody(), true);

    }

    protected function mapUserToObject(array $user): User
    {
        return (new User)->setRaw($user)->map([
            'id' => $user['id'],
            'name' => $user['name'] ?? '',
            'email' => $user['email'] ?? '',
            'avatar' => $user['avatar'] ?? '',
        ]);
    }

    /**
     * @throws GuzzleException
     */
    public function logout($token)
    {
        return $this->getHttpClient()->post(
            $this->host.'/api/v1/oauth/logout', $this->getRequestOptions($token)
        );
    }

    protected function getRequestOptions($token): array
    {
        return [
            RequestOptions::HEADERS => [
                'Accept' => 'application/json',
                'Authorization' => 'Bearer '.$token,
            ],
        ];
    }
}
