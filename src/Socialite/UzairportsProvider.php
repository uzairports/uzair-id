<?php

namespace Uzairports\Uzairid\Socialite;

use GuzzleHttp\Exception\GuzzleException;
use GuzzleHttp\RequestOptions;
use Laravel\Socialite\Two\AbstractProvider;
use Laravel\Socialite\Two\ProviderInterface;
use Laravel\Socialite\Two\User;
use Psr\Http\Message\ResponseInterface;

class UzairportsProvider extends AbstractProvider implements ProviderInterface
{
    protected string $host = 'https://my.uzairports.com';

    /** @var array<array-key, string> */
    protected $scopes = [];

    public function getHost(): string
    {
        return $this->host;
    }

    protected function getAuthUrl($state): string
    {
        return $this->buildAuthUrlFromBase($this->getHost().'/oauth/authorize', $state);
    }

    protected function getTokenUrl(): string
    {
        return $this->getHost().'/oauth/token';
    }

    /**
     * @throws GuzzleException
     */
    protected function getUserByToken($token)
    {
        $response = $this->getHttpClient()->get(
            $this->getHost().'/api/user', $this->getRequestOptions($token)
        );

        return json_decode((string) $response->getBody(), true) ?? [];
    }

    /**
     * @param  array<array-key, mixed>  $user
     */
    protected function mapUserToObject(array $user): User
    {
        return (new User)->setRaw($user)->map([
            'id' => $user['id'] ?? null,
            'name' => $user['name'] ?? '',
            'email' => $user['email'] ?? '',
            'avatar' => $user['avatar'] ?? '',
        ]);
    }

    /**
     * @throws GuzzleException
     */
    public function logout(string $token): ResponseInterface
    {
        return $this->getHttpClient()->post(
            $this->getHost().'/api/v1/oauth/logout', $this->getRequestOptions($token)
        );
    }

    /**
     * @return array<string, array<string, string>>
     */
    protected function getRequestOptions(string $token): array
    {
        return [
            RequestOptions::HEADERS => [
                'Accept' => 'application/json',
                'Authorization' => 'Bearer '.$token,
            ],
        ];
    }
}
