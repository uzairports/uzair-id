<?php

namespace Uzairports\Uzairid\Socialite;

use GuzzleHttp\RequestOptions;
use Laravel\Socialite\Two\AbstractProvider;
use Laravel\Socialite\Two\ProviderInterface;
use Laravel\Socialite\Two\User;

class UzairportsProvider extends AbstractProvider implements ProviderInterface
{

    protected string $host = 'https://my.uzairports.com';
    protected $scopes = [];

    protected function getAuthUrl($state)
    {
        return $this->buildAuthUrlFromBase($this->host . '/oauth/authorize', $state);
    }

    protected function getTokenUrl()
    {
        return $this->host . '/oauth/token';
    }

    protected function getUserByToken($token)
    {
        $response = $this->getHttpClient()->get(
            $this->host . '/api/user', $this->getRequestOptions($token)
        );

        return json_decode($response->getBody(), true);

    }

    protected function mapUserToObject(array $user)
    {
        return (new User)->setRaw($user)->map([
            'id' => $user['id'],
            'name' => $user['name'] ?? '',
            'email' => $user['name'] ?? '',
            'avatar' => $user['avatar'] ?? '',
        ]);
    }

    protected function getRequestOptions($token)
    {
        return [
            RequestOptions::HEADERS => [
                'Accept' => 'application/json',
                'Authorization' => 'Bearer '.$token,
            ],
        ];
    }
}
