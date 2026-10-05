<?php

namespace Uzairports\Uzairid\Socialite;

use GuzzleHttp\Exception\GuzzleException;
use GuzzleHttp\Promise\PromiseInterface;
use GuzzleHttp\RequestOptions;
use Illuminate\Support\Arr;
use Illuminate\Support\Facades\Log;
use Laravel\Socialite\Two\AbstractProvider;
use Laravel\Socialite\Two\InvalidStateException;
use Laravel\Socialite\Two\ProviderInterface;
use Laravel\Socialite\Two\User;
use Psr\Http\Message\ResponseInterface;
use RuntimeException;
use Throwable;
use Uzairports\Uzairid\Actions\EndSessions;

class UzairportsProvider extends AbstractProvider implements ProviderInterface
{
    private const string DEFAULT_HOST = 'https://my.uzairports.com';

    /** @var array<array-key, string> */
    protected $scopes = [];

    /**
     * OAuth 2.0 defines the `scope` parameter as a space-delimited list, which
     * is what the identity provider expects and reports back.
     *
     * @var string
     */
    protected $scopeSeparator = ' ';

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
     * The refresh exchange and its lock must use the same finite timeout.
     */
    public static function requestTimeout(): int
    {
        return self::seconds(config('uzairports.guzzle.timeout', config('uzairports.timeout', 10)), 10);
    }

    /**
     * Complete the handshake, giving the grants up if the profile cannot be read.
     *
     * Overrides Socialite's `user()`: when the profile request fails after a
     * successful exchange, the issued grants exist only here, so they are
     * surrendered before the failure is rethrown. Failures after a user exists
     * are handled by `UzairAuthController`.
     *
     * @throws InvalidStateException when the callback carries no matching state
     * @throws GuzzleException
     * @throws Throwable
     */
    public function user(): User
    {
        if ($this->user) {
            return $this->user;
        }

        if ($this->hasInvalidState()) {
            throw new InvalidStateException;
        }

        return $this->exchange($this->getCode());
    }

    /**
     * Exchange an authorization code a mobile client obtained by itself.
     *
     * The client checked its own `state`; its PKCE verifier is passed through so
     * an intercepted code cannot be redeemed here. The exchange runs on a clone
     * so the shared driver instance keeps no redirect URI or verifier.
     *
     * @throws GuzzleException
     * @throws Throwable
     */
    public function userFromCode(string $code, string $redirectUri, ?string $codeVerifier): User
    {
        $exchange = clone $this;

        $exchange->user = null;
        $exchange->stateless = true;
        $exchange->redirectUrl = $redirectUri;
        // No session verifier; the client's is sent as an extra field instead.
        $exchange->usesPKCE = false;

        if ($codeVerifier !== null && $codeVerifier !== '') {
            $exchange->parameters = array_merge($exchange->parameters, ['code_verifier' => $codeVerifier]);
        }

        return $exchange->exchange($code);
    }

    /**
     * Exchange the code and read the profile behind it.
     *
     * @param  string  $code  as Socialite reads it off the request, which may be null
     *
     * @throws GuzzleException
     * @throws Throwable
     */
    private function exchange($code): User
    {
        $response = $this->getAccessTokenResponse($code);

        try {
            $profile = $this->getUserByToken($response['access_token']);

            return $this->userInstance($response, $profile);
        } catch (Throwable $exception) {
            $this->user = null;
            $this->surrenderIssuedGrants($response);

            throw $exception;
        }
    }

    /**
     * Give up the grants of a handshake that got no further than the exchange.
     *
     * Routed through `EndSessions` so both grants are revoked together. Never
     * throws, so the original failure is what the caller sees.
     *
     * @param  array<array-key, mixed>  $response
     */
    private function surrenderIssuedGrants(array $response): void
    {
        try {
            app(EndSessions::class)->surrenderIssued(
                Arr::get($response, 'access_token'),
                Arr::get($response, 'refresh_token'),
            );
        } catch (Throwable $exception) {
            Log::warning('Failed to surrender the grants of an UzAirports handshake whose profile could not be read.', [
                'exception_class' => $exception::class,
            ]);
        }
    }

    /**
     * @return array{access_token: string, ...}
     *
     * @throws GuzzleException
     */
    public function getAccessTokenResponse($code): array
    {
        $response = $this->getHttpClient()->post($this->getTokenUrl(), [
            RequestOptions::TIMEOUT => self::requestTimeout(),
            RequestOptions::CONNECT_TIMEOUT => min($this->connectTimeout(), self::requestTimeout()),
            RequestOptions::ALLOW_REDIRECTS => false,
            RequestOptions::HEADERS => $this->getTokenHeaders($code),
            RequestOptions::FORM_PARAMS => $this->getTokenFields($code),
        ]);

        return $this->decodeTokenResponse($response);
    }

    /** @return array<array-key, mixed>
     * @throws GuzzleException
     */
    protected function getRefreshTokenResponse($refreshToken): array
    {
        $response = $this->getHttpClient()->post($this->getTokenUrl(), [
            RequestOptions::TIMEOUT => self::requestTimeout(),
            RequestOptions::CONNECT_TIMEOUT => min($this->connectTimeout(), self::requestTimeout()),
            RequestOptions::ALLOW_REDIRECTS => false,
            RequestOptions::HEADERS => ['Accept' => 'application/json'],
            RequestOptions::FORM_PARAMS => [
                'grant_type' => 'refresh_token',
                'refresh_token' => $refreshToken,
                'client_id' => $this->clientId,
                'client_secret' => $this->clientSecret,
            ],
        ]);

        $decoded = $this->decodeTokenResponse($response);

        $decoded['refresh_token'] = is_string($decoded['refresh_token'] ?? null) ? $decoded['refresh_token'] : '';
        $decoded['expires_in'] = is_numeric($decoded['expires_in'] ?? null) ? (int) $decoded['expires_in'] : 0;

        return $decoded;
    }

    /**
     * @return array{access_token: string, ...}
     */
    private function decodeTokenResponse(ResponseInterface $response): array
    {
        $decoded = json_decode((string) $response->getBody(), true);

        if ($response->getStatusCode() < 200 || $response->getStatusCode() >= 300
            || ! is_array($decoded) || ! is_string($decoded['access_token'] ?? null) || trim($decoded['access_token']) === '') {
            throw new RuntimeException('UzAirports SSO returned an invalid token response.');
        }

        return $decoded;
    }

    /**
     * Read the profile behind an access token.
     *
     * Like every request here, redirects are disallowed and the answer must be
     * a 2xx JSON object. The status is checked explicitly because `http_errors`
     * may be turned off and a 3xx comes back as an ordinary response.
     *
     * @return array<array-key, mixed>
     *
     * @throws GuzzleException
     * @throws RuntimeException when the identity provider answers with anything but a 2xx JSON object
     */
    protected function getUserByToken($token): array
    {
        $endpoint = config('uzairports.user_endpoint', '/api/user');
        $url = is_string($endpoint) && $endpoint !== ''
            ? $this->absoluteUrl($endpoint)
            : $this->getHost().'/api/user';

        $response = $this->getHttpClient()->get(
            $url, $this->getRequestOptions((string) $token)
        );

        if ($response->getStatusCode() < 200 || $response->getStatusCode() >= 300) {
            throw new RuntimeException('UzAirports SSO did not answer with a user profile.');
        }

        $decoded = json_decode((string) $response->getBody(), true);

        if (! is_array($decoded)) {
            throw new RuntimeException('UzAirports SSO returned a user profile that is not a JSON object.');
        }

        return $decoded;
    }

    /**
     * @param  array<array-key, mixed>  $user
     */
    protected function mapUserToObject(array $user): User
    {
        return (new User)->setRaw($user)->map([
            'id' => $user['id'] ?? $user['sub'] ?? null,
            'name' => $user['name'] ?? '',
            'email' => $user['email'] ?? '',
            'avatar' => $user['avatar'] ?? '',
        ]);
    }

    public function logout(string $token): ?ResponseInterface
    {
        return $this->wait($this->logoutAsync($token));
    }

    /**
     * Hand the access token back without waiting for the answer.
     *
     * Returned as a promise so revocations for many logins run concurrently and
     * the caller waits once. Null means no endpoint is configured.
     */
    public function logoutAsync(string $token): ?PromiseInterface
    {
        $endpoint = config('uzairports.logout_endpoint', '/api/oauth/logout');

        if (! is_string($endpoint) || $endpoint === '') {
            return null;
        }

        return $this->confirmed($this->getHttpClient()->postAsync(
            $this->absoluteUrl($endpoint), $this->getRequestOptions($token, $this->revocationTimeout())
        ));
    }

    /**
     * Give a refresh token up at the identity provider, per RFC 7009.
     *
     * Revoking the access token does not guarantee the refresh token is
     * retired, so it is revoked explicitly. The endpoint is not guessed: without
     * `uzairports.revoke_endpoint` this returns null.
     */
    public function revokeRefreshToken(string $refreshToken): ?ResponseInterface
    {
        return $this->wait($this->revokeRefreshTokenAsync($refreshToken));
    }

    /**
     * Surrender the refresh token without waiting for the answer.
     *
     * Sent alongside the access-token revocation; see `logoutAsync()`.
     */
    public function revokeRefreshTokenAsync(string $refreshToken): ?PromiseInterface
    {
        $endpoint = config('uzairports.revoke_endpoint');

        if (! is_string($endpoint) || $endpoint === '') {
            return null;
        }

        $revocationTimeout = $this->revocationTimeout();

        return $this->confirmed($this->getHttpClient()->postAsync($this->absoluteUrl($endpoint), [
            RequestOptions::TIMEOUT => $revocationTimeout,
            RequestOptions::CONNECT_TIMEOUT => min($this->connectTimeout(), $revocationTimeout),
            RequestOptions::ALLOW_REDIRECTS => false,
            RequestOptions::HEADERS => ['Accept' => 'application/json'],
            RequestOptions::FORM_PARAMS => [
                'token' => $refreshToken,
                'token_type_hint' => 'refresh_token',
                'client_id' => $this->clientId,
                'client_secret' => $this->clientSecret,
            ],
        ]));
    }

    /**
     * Hold the promise to the same answer the waited-on call demanded.
     *
     * Only a 2xx confirms revocation; anything else rejects the promise.
     */
    private function confirmed(PromiseInterface $promise): PromiseInterface
    {
        return $promise->then(function (mixed $response): ResponseInterface {
            if (! $response instanceof ResponseInterface) {
                throw new RuntimeException('UzAirports SSO did not answer the revocation request.');
            }

            return $this->ensureRevoked($response);
        });
    }

    /**
     * Wait out a revocation, giving up whatever it was rejected with.
     */
    private function wait(?PromiseInterface $promise): ?ResponseInterface
    {
        if ($promise === null) {
            return null;
        }

        $response = $promise->wait();

        return $response instanceof ResponseInterface ? $response : null;
    }

    private function ensureRevoked(ResponseInterface $response): ResponseInterface
    {
        if ($response->getStatusCode() < 200 || $response->getStatusCode() >= 300) {
            throw new RuntimeException('UzAirports SSO did not confirm token revocation.');
        }

        return $response;
    }

    /**
     * Resolve a configured endpoint, which may be a full URL or a path on the host.
     */
    private function absoluteUrl(string $endpoint): string
    {
        if (str_starts_with($endpoint, 'http://') || str_starts_with($endpoint, 'https://')) {
            return $endpoint;
        }

        return $this->getHost().'/'.ltrim($endpoint, '/');
    }

    /**
     * @return array{timeout: int, connect_timeout: int, allow_redirects: false, headers: array{Accept: string, Authorization: string}}
     */
    protected function getRequestOptions(string $token, ?int $timeout = null): array
    {
        $effectiveTimeout = $timeout ?? $this->timeout();

        return [
            RequestOptions::TIMEOUT => $effectiveTimeout,
            RequestOptions::CONNECT_TIMEOUT => min($this->connectTimeout(), $effectiveTimeout),
            RequestOptions::ALLOW_REDIRECTS => false,
            RequestOptions::HEADERS => [
                'Accept' => 'application/json',
                'Authorization' => 'Bearer '.$token,
            ],
        ];
    }

    private function timeout(): int
    {
        return self::requestTimeout();
    }

    private function connectTimeout(): int
    {
        return self::seconds(config('uzairports.guzzle.connect_timeout', config('uzairports.connect_timeout', 5)), 5);
    }

    public static function revocationTimeout(): int
    {
        return self::seconds(config('uzairports.revocation_timeout', 3), 3);
    }

    private static function seconds(mixed $value, int $default): int
    {
        return is_numeric($value) && (float) $value > 0 ? (int) ceil((float) $value) : $default;
    }
}
