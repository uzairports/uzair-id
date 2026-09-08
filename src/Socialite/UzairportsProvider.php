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
    private const string DEFAULT_HOST = 'https://my.uzairports.com';

    /** @var array<array-key, string> */
    protected $scopes = [];

    protected ?string $host = null;

    public function setHost(?string $host): static
    {
        $this->host = $host;

        return $this;
    }

    /**
     * The base address every OAuth and API call is built on.
     *
     * It is read from the configuration on each call so that the host can be
     * pointed at a staging instance without rebuilding the driver.
     */
    public function getHost(): string
    {
        if (is_string($this->host) && $this->host !== '') {
            return rtrim($this->host, '/');
        }

        $host = config('uzairports.host');

        return rtrim(is_string($host) && $host !== '' ? $host : self::DEFAULT_HOST, '/');
    }

    protected function getAuthUrl($state): string
    {
        return $this->buildAuthUrlFromBase($this->getHost().'/oauth/authorize', (string) $state);
    }

    protected function getTokenUrl(): string
    {
        return $this->getHost().'/oauth/token';
    }

    /**
     * @return array<array-key, mixed>
     *
     * @throws GuzzleException
     */
    protected function getUserByToken($token): array
    {
        $response = $this->getHttpClient()->get(
            $this->getHost().'/api/user', $this->getRequestOptions((string) $token)
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
     * @return array<string, mixed>
     */
    protected function getRequestOptions(string $token): array
    {
        return [
            RequestOptions::TIMEOUT => (int) ($this->config['timeout'] ?? config('uzairports.timeout', 10)),
            RequestOptions::CONNECT_TIMEOUT => (int) ($this->config['connect_timeout'] ?? config('uzairports.connect_timeout', 5)),
            RequestOptions::HEADERS => [
                'Accept' => 'application/json',
                'Authorization' => 'Bearer '.$token,
            ],
        ];
    }
}
