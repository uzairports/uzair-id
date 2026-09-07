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
    | Login Route
    |--------------------------------------------------------------------------
    |
    | The named route users are sent to when their session can no longer be
    | renewed and they have to authenticate again.
    |
    */

    'login_route' => env('UZAIR_LOGIN_ROUTE', 'login'),

];
