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
     * This is Socialite's own `user()` with one thing added, and it is added
     * here because there is nowhere else it can go. The exchange happens first
     * and the profile request second, so a provider that answers the first and
     * fails the second has already issued a live access token and a live
     * refresh token — and `user()` throws instead of returning them, so the
     * caller never sees the grants it would have to hand back. They exist only
     * as a local variable in this method.
     *
     * Both halves of a callback that cannot be completed are answered the same
     * way now: the driver surrenders what fails here, and
     * `UzairAuthController` surrenders what fails after it has a user.
     *
     * The profile request is the likelier of the two to fail — it is a second
     * round trip to the identity provider, with its own timeout — so leaving it
     * uncovered left the more common failure leaking grants.
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

        $response = $this->getAccessTokenResponse($this->getCode());

        try {
            $profile = $this->getUserByToken($response['access_token']);
        } catch (Throwable $exception) {
            $this->surrenderIssuedGrants($response);

            throw $exception;
        }

        return $this->userInstance($response, $profile);
    }

    /**
     * Give up the grants of a handshake that got no further than the exchange.
     *
     * Routed through `EndSessions` like every other revocation in the package,
     * so both grants go on the wire together, and a refusal is reported the same
     * way. Nothing raises: the caller is about to be handed the failure that
     * brought it here, which is the one worth reading.
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
     * Two things are asked of the answer, and the token exchange beside this
     * has always asked both — see `decodeTokenResponse()`.
     *
     * The status comes first. Guzzle raises a 4xx or a 5xx on its own only
     * while `http_errors` is left on, and `uzairports.guzzle` is merged into the
     * client, so an application is free to turn it off. A redirect is not
     * covered by that setting at all: these requests carry
     * `ALLOW_REDIRECTS => false`, so a 302 comes back as an ordinary response —
     * and a gateway in front of the identity provider answering one with a body
     * of its own was mapped into a user and signed in. Whatever a non-2xx
     * carries, it is not a profile this provider vouched for.
     *
     * Then the body. Anything that is not a JSON object — an empty response, a
     * bare string, a page of HTML — decodes to something this method cannot
     * map, and is reported as such rather than handed on as a malformed
     * profile. The account behind it is still refused twice over:
     * `ResolveUserFromSocialite` turns down a profile carrying no id.
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
            'id' => $user['id'] ?? null,
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
     * Ending several logins at once means one of these per login, and each
     * carries the provider's revocation timeout. Waited on in turn they add up:
     * an account signed in on a dozen devices spent a dozen timeouts inside the
     * request a browser was holding. Handed back as a promise they are put on
     * the wire together and the caller waits once, for the slowest.
     *
     * Null means there is no endpoint configured to call, which is not a
     * failure — the identity provider simply offers no such endpoint.
     */
    public function logoutAsync(string $token): ?PromiseInterface
    {
        $endpoint = config('uzairports.logout_endpoint', '/api/v1/oauth/logout');

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
     * `logout()` hands back the access token, which is all the identity
     * provider is told about. Whether that also retires the refresh token
     * issued alongside it is the provider's business. Nothing in the
     * protocol promises it does — so where a revocation endpoint exists, the
     * refresh token is surrendered explicitly rather than left to a cascade
     * that may not happen. A refresh token that survives a logout is a way back
     * into the account for whoever holds a copy of it.
     *
     * The endpoint is not guessed: without `uzairports.revoke_endpoint` there
     * is nothing to call, and the method says so by returning null, so a
     * deployment whose provider offers no such endpoint pays no failed request
     * on every logout.
     */
    public function revokeRefreshToken(string $refreshToken): ?ResponseInterface
    {
        return $this->wait($this->revokeRefreshTokenAsync($refreshToken));
    }

    /**
     * Surrender the refresh token without waiting for the answer.
     *
     * The access token and the refresh token of one login are surrendered
     * independently — neither answer decides the other — so they travel
     * together rather than one after the next. See `logoutAsync()` for why the
     * waiting is done once, by the caller.
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
     * A 2xx is what says the grant was actually given up. Anything else is
     * turned into a rejection here rather than at the point of waiting, so a
     * caller settling many of these reads one kind of outcome for all of them.
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
     * @return array<string, mixed>
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
