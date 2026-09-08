<?php

return [

    /*
    |--------------------------------------------------------------------------
    | OAuth Client
    |--------------------------------------------------------------------------
    |
    | The credentials issued by UzAirports ID. The redirect URL has to match the
    | one registered for the client, and is the address of the route calling
    | the callback action.
    |
    */

    'client_id' => env('UZAIR_CLIENT_ID'),

    'client_secret' => env('UZAIR_CLIENT_SECRET'),

    'redirect' => env('UZAIR_CALLBACK_URL'),

    /*
    |--------------------------------------------------------------------------
    | Identity Provider Host
    |--------------------------------------------------------------------------
    |
    | The base address every OAuth and API call is built on. Override it to
    | point the application at a staging instance of UzAirports ID.
    |
    */

    'host' => env('UZAIR_HOST', 'https://my.uzairports.com'),

    /*
    |--------------------------------------------------------------------------
    | Token Revocation Endpoint
    |--------------------------------------------------------------------------
    |
    | Where the refresh token is surrendered when a login ends, as an RFC 7009
    | revocation request. Signing out hands the access token back, and nothing
    | in OAuth promises that retires the refresh token issued with it — one that
    | survives is a way back into the account for whoever holds a copy.
    |
    | Empty means the identity provider offers no such endpoint and only the
    | access token is given up. Accepts a full URL or a path on the host.
    |
    */

    'revoke_endpoint' => env('UZAIR_REVOKE_ENDPOINT'),

    /*
    |--------------------------------------------------------------------------
    | Revoke Grants When Pruning
    |--------------------------------------------------------------------------
    |
    | Whether the cleanup gives each login's grant up at the identity provider
    | before dropping its row. A closed browser never signs out, so without
    | this its refresh token stays honoured long after nothing here points at
    | it — which is the one way a login can end holding a live grant.
    |
    | It costs the provider's revocation calls per row, in a command that may
    | be sweeping thousands. Turn it off only where that backlog is real and
    | the grants expire on their own.
    |
    */

    'revoke_on_prune' => (bool) env('UZAIR_REVOKE_ON_PRUNE', true),

    /*
    |--------------------------------------------------------------------------
    | Proof Key for Code Exchange
    |--------------------------------------------------------------------------
    |
    | Whether the authorization code is bound to a one-time verifier, so that a
    | code intercepted on its way back cannot be redeemed by anyone else. Turn
    | it off only for an identity provider that rejects `code_challenge`.
    |
    */

    'pkce' => (bool) env('UZAIR_PKCE', true),

    /*
    |--------------------------------------------------------------------------
    | Scopes
    |--------------------------------------------------------------------------
    |
    | The scopes requested on the authorization URL, as a space-separated list.
    | Empty means the identity provider decides what the token may reach.
    |
    */

    'scopes' => array_values(array_filter(
        explode(' ', (string) env('UZAIR_SCOPES', ''))
    )),

    /*
    |--------------------------------------------------------------------------
    | Refresh Leeway
    |--------------------------------------------------------------------------
    |
    | How many seconds before the actual expiry the `uzair.token` middleware
    | renews the access token. The leeway has to cover the time a request
    | spends using the token, so it does not expire mid-flight.
    |
    */

    'refresh_leeway' => (int) env('UZAIR_REFRESH_LEEWAY', 60),

    /*
    |--------------------------------------------------------------------------
    | Default Token TTL
    |--------------------------------------------------------------------------
    |
    | When the identity provider does not return an `expires_in` parameter in
    | the token refresh response, this value (in seconds) is used as fallback
    | TTL so that the token is not continuously treated as expired on every
    | subsequent request.
    |
    */

    'default_token_ttl' => (int) env('UZAIR_DEFAULT_TOKEN_TTL', 3600),

    /*
    |--------------------------------------------------------------------------
    | Login Route
    |--------------------------------------------------------------------------
    |
    | The named route users are sent to when their session can no longer be
    | renewed and they have to authenticate again.
    |
    */

    'login_route' => env('UZAIR_LOGIN_ROUTE', 'login'),

    /*
    |--------------------------------------------------------------------------
    | Default Redirect Destination
    |--------------------------------------------------------------------------
    |
    | The route or path users are redirected to after a successful login if no
    | previous intended URL was recorded in the session.
    |
    */

    'redirect_to' => env('UZAIR_REDIRECT_TO', 'dashboard'),

    /*
    |--------------------------------------------------------------------------
    | Redirect Destinations Around the Flow
    |--------------------------------------------------------------------------
    |
    | Where the user lands when the handshake could not be completed, and where
    | a browser goes after logging out. Both accept a route name or a path.
    |
    */

    'redirect_on_error' => env('UZAIR_REDIRECT_ON_ERROR', '/'),

    'redirect_after_logout' => env('UZAIR_REDIRECT_AFTER_LOGOUT', '/'),

    /*
    |--------------------------------------------------------------------------
    | Routes
    |--------------------------------------------------------------------------
    |
    | Defaults for the routes `Uzair::routes()` registers. The throttle is an
    | `attempts,minutes` pair spent per browser, not per address: an office
    | behind one NAT gateway is a single address, and a limit low enough to be
    | worth having would lock everyone out the moment a few colleagues signed in
    | together. One sign-in costs two requests — the redirect and the callback —
    | so the budget is generous by design. Set it to null to lift the limit.
    |
    */

    'routes' => [

        'prefix' => env('UZAIR_ROUTE_PREFIX', 'auth'),

        'throttle' => env('UZAIR_ROUTE_THROTTLE', '60,1'),

    ],

    /*
    |--------------------------------------------------------------------------
    | Single Active Session
    |--------------------------------------------------------------------------
    |
    | Whether signing in ends every other login the account holds, leaving only
    | the browser that just authenticated. Off by default: an account is
    | normally allowed a phone and a desktop at once, and users who want the
    | rest gone have the "sign-out everywhere" endpoint to say so. Turn it on
    | only where concurrent use is something you have to prevent.
    |
    */

    'single_session' => (bool) env('UZAIR_SINGLE_SESSION', false),

    /*
    |--------------------------------------------------------------------------
    | Account Linking by Email
    |--------------------------------------------------------------------------
    |
    | Whether existing local accounts without an UzAirports ID should be
    | claimed by email on first SSO login. It is off by default: the identity
    | provider does not promise the address it reports was ever verified, so
    | turn it on only for a one-off migration you are willing to stand behind.
    |
    */

    'link_by_email' => (bool) env('UZAIR_LINK_BY_EMAIL', false),

    /*
    |--------------------------------------------------------------------------
    | HTTP Client Timeouts
    |--------------------------------------------------------------------------
    |
    | Request timeout and connection timeout in seconds for calls to the
    | identity provider.
    |
    */

    'timeout' => (int) env('UZAIR_TIMEOUT', 10),

    'connect_timeout' => (int) env('UZAIR_CONNECT_TIMEOUT', 5),

    'revocation_timeout' => (int) env('UZAIR_REVOCATION_TIMEOUT', 3),

    /*
    |--------------------------------------------------------------------------
    | Lock Cache Store
    |--------------------------------------------------------------------------
    |
    | The cache store used for atomic locks during token refresh. When null,
    | the application's default cache store is used.
    |
    */

    'lock_store' => env('UZAIR_LOCK_STORE'),

];
