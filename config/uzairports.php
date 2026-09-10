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
    | Access Token Logout Endpoint
    |--------------------------------------------------------------------------
    |
    | The endpoint called to surrender the access token when a user logs out.
    | Set to empty or null if the identity provider does not support access token
    | revocation. Accepts a full URL or a path on the host.
    |
    */

    'logout_endpoint' => env('UZAIR_LOGOUT_ENDPOINT', '/api/v1/oauth/logout'),

    /*
    |--------------------------------------------------------------------------
    | User Profile Endpoint
    |--------------------------------------------------------------------------
    |
    | Where the user profile is fetched using the issued access token.
    | Accepts a full URL or a path on the host.
    |
    */

    'user_endpoint' => env('UZAIR_USER_ENDPOINT', '/api/user'),

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
    | When the identity provider does not return an `expires_in` parameter — or
    | returns a zero — this value (in seconds) stands in for it, so that the
    | token is not treated as expired on every subsequent request.
    |
    | It applies wherever a token is stored: the code exchange that opens a
    | session and the refresh that renews one. Sign-in used to leave the expiry
    | unknown instead, which the middleware reads as expired, so the first
    | request after every sign-in spent the refresh token on an exchange that
    | arrived at this same value.
    |
    | Zero, or anything that is not a number, leaves the expiry unknown. The
    | token is then renewed on next use rather than trusted for a guess.
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
    | Which browser a request belongs to is read off the session cookie it
    | carries, and a caller writes its own cookies: one arriving with a fresh
    | session id every time is a fresh browser every time, and the budget above
    | never catches it. `ip_throttle` is the ceiling that does — the same kind
    | of pair, spent per address, and the limit that actually holds for a caller
    | that rotates its cookie. It has to clear a whole NAT gateway's worth of
    | genuine sign-ins, so raise it where one address really does carry that
    | many; set it to null to leave the address uncapped.
    |
    */

    'routes' => [

        'prefix' => env('UZAIR_ROUTE_PREFIX', 'auth'),

        'throttle' => env('UZAIR_ROUTE_THROTTLE', '60,1'),

        'ip_throttle' => env('UZAIR_ROUTE_IP_THROTTLE', '120,1'),

    ],

    /*
    |--------------------------------------------------------------------------
    | Single Active Session
    |--------------------------------------------------------------------------
    |
    | Whether signing in ends every other login the account holds, leaving only
    | the browser that just authenticated. Off by default: an account is
    | normally allowed a phone and a desktop at once, and a user who wants one
    | of the others gone ends it from the list of their own logins, through
    | `uzair.logoutDevice`. Turn it on only where concurrent use is something
    | you have to prevent.
    |
    | It is not free: every login being ended is surrendered to the identity
    | provider in turn, inside the callback the browser is waiting on, so an
    | account signed in on several devices pays a revocation round-trip for
    | each of them before it is let in. `revoke_on_single_session` below is
    | where that bill is refused.
    |
    */

    'single_session' => (bool) env('UZAIR_SINGLE_SESSION', false),

    /*
    |--------------------------------------------------------------------------
    | Revoke Grants When a Sign-In Ends the Others
    |--------------------------------------------------------------------------
    |
    | Whether `single_session` gives each login's grant up at the identity
    | provider before letting the new one in. On by default, because a grant
    | nobody surrendered keeps being honoured: whoever holds a copy of that
    | refresh token has a way into the account until it expires on its own.
    |
    | The cost falls on the one request a user is actually waiting on, and it
    | grows with the number of devices the account is signed in on — an account
    | on a dozen of them waits out a dozen revocation timeouts before it sees
    | the dashboard. Turn it off where that wait is real: the logins still end
    | here — rows dropped, sessions deleted, `uzair.token` refusing them on
    | their next request — and only the remote surrender is given up.
    |
    */

    'revoke_on_single_session' => (bool) env('UZAIR_REVOKE_ON_SINGLE_SESSION', true),

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
    | Identity Provider Cooldown
    |--------------------------------------------------------------------------
    |
    | How many seconds the token exchange is left unattempted after the identity
    | provider fails to answer one.
    |
    | Without it, an unreachable provider costs every request holding an
    | expiring token the full `timeout` above before it is answered, and those
    | waits are held in the application's workers — of which there are far fewer
    | than there are requests during a wave of expiries. A provider that is
    | merely unreachable then takes the whole application down with it, pages
    | that never needed a token included.
    |
    | Enough failures stand for the ones behind them instead: for this long the
    | provider is left alone, and those requests are answered from what is
    | stored — by adopting a login another process renewed, or by a 503 that
    | costs nothing. Nobody is signed out over it.
    |
    | The entry lapses rather than being probed, so traffic reaches the provider
    | again for one `timeout` in every cooldown. Set it to several times that
    | timeout, or a shorter value spares little; zero calls the provider on
    | every renewal however it answered the last one.
    |
    */

    'provider_cooldown' => (int) env('UZAIR_PROVIDER_COOLDOWN', 30),

    /*
    |--------------------------------------------------------------------------
    | Identity Provider Failure Threshold
    |--------------------------------------------------------------------------
    |
    | How many failures within one cooldown are an outage rather than a hiccup.
    |
    | A single dropped connection, rate limit or malformed response costs one
    | request one timeout, and happens to healthy providers. Standing each of
    | them up as an outage would stop the whole application renewing logins for
    | a cooldown every time one occurred — the very failure the cooldown exists
    | to prevent, self-inflicted.
    |
    | An exchange that succeeds clears the count, so failures spread apart never
    | add up. Set it to 1 to leave the provider alone after the first one.
    |
    */

    'provider_failure_threshold' => (int) env('UZAIR_PROVIDER_FAILURE_THRESHOLD', 5),

    /*
    |--------------------------------------------------------------------------
    | Revocation Concurrency
    |--------------------------------------------------------------------------
    |
    | How many grants are handed back to the identity provider at once when
    | several logins end together. Each revocation carries the timeout above,
    | and there are up to two per login, so sending them in turn made the wait
    | the sum of them all — worst inside the callback `single_session` ends the
    | account's other logins in.
    |
    | Raising it shortens that wait and opens more sockets at once; lowering it
    | to 1 restores the old one-at-a-time behaviour.
    |
    */

    'revocation_concurrency' => (int) env('UZAIR_REVOCATION_CONCURRENCY', 10),

    /*
    |--------------------------------------------------------------------------
    | Resolved Login Lifetime
    |--------------------------------------------------------------------------
    |
    | How many seconds the `uzair.token` middleware may let a request through
    | on the login it last resolved for that session, instead of reading the
    | row again. Every request through the middleware otherwise costs one read
    | of `oauth_tokens` to ask two questions whose answer, for a browser
    | clicking around, is the same nearly every time.
    |
    | Zero — the default — reads the row on every request, which is the only
    | setting under which a login ended anywhere at all is refused on the very
    | next request. Above zero, every path in this package that ends a login
    | also drops the entry, so signing a device out from another one still
    | takes effect at once wherever the two share a cache store. What the
    | lifetime covers is a row that went away without the package knowing: a
    | sweep, or a delete run by hand against the database.
    |
    | Keep it well under the session lifetime — a few seconds is enough to take
    | the read off a busy page — and leave it at zero if a login must never
    | outlive its row by even that much.
    |
    | What it saves is the read on requests that only need the login to still be
    | there, which is nearly all of them. A request that goes on to ask for the
    | token itself — `$user->getUzairAccessToken()`, `$user->currentToken()` —
    | reads the row anyway, and no setting can change that: the entry holds the
    | account and the expiry and never the token, which lives under an encrypted
    | cast and has no business in a cache store. Expect this to do nothing for
    | an endpoint that calls the identity provider on the user's behalf.
    |
    | Above zero this rests on `login_cache_store` below being a store every
    | process shares.
    |
    */

    'login_cache_ttl' => (int) env('UZAIR_LOGIN_CACHE_TTL', 0),

    /*
    |--------------------------------------------------------------------------
    | Resolved Login Cache Store
    |--------------------------------------------------------------------------
    |
    | The cache store the resolved logins are kept in. When null, the
    | application's default cache store is used.
    |
    | It has to be a store every process serving this application reads, for the
    | same reason `lock_store` does: ending a login forgets its entry, and a
    | process that cannot see that entry keeps letting the device through until
    | the lifetime above lapses. `redis`, `memcached` and `database` are shared;
    | `array` is held in the memory of one process, and `file` is shared on one
    | server but not between several, so on more than one machine a device
    | signed out on one of them stays signed in on the others.
    |
    | A store that is provably not shared is reported in the log once. Nothing
    | is refused over it — an entry nobody can find behaves exactly like
    | `login_cache_ttl` being zero.
    |
    | This is where to point the entries when the application caches in
    | something unshared but a store every process reads is available.
    |
    */

    'login_cache_store' => env('UZAIR_LOGIN_CACHE_STORE'),

    /*
    |--------------------------------------------------------------------------
    | Lock Cache Store
    |--------------------------------------------------------------------------
    |
    | The cache store used for atomic locks during token refresh. When null,
    | the application's default cache store is used.
    |
    | The refresh token rotates and may only be spent once, and the lock is the
    | only thing standing between two requests spending the same one — so the
    | store has to be one every process serving this application shares.
    | `redis`, `memcached` and `database` are; `array` is held in the memory of
    | one process, and `file` is shared on one server but not between several,
    | so on more than one machine it guards nothing. A store that is provably
    | not shared, or that offers no locks at all, is reported in the log once
    | and the exchange runs unguarded rather than failing the sign-in.
    |
    */

    'lock_store' => env('UZAIR_LOCK_STORE'),

];
