<?php

use Illuminate\Http\Request;
use Illuminate\Contracts\Auth\Authenticatable;
/*
 * Configurable:
 * - cookie and request input key to use as fallback is token
 * not present in Authorization Header with Bearer schema
 * - claim to use as User identitifier and Authenticatable Model
 * - expiration time and key used to sign tokens
 * - guard, driver and provider to insert in authentication
 */
return [
    /*
    | cookie used as first fallback if token not sent
    | in Authorization Header
    */
    'cookie' => 'token',

    /*
    | custom request user input key to use as 2nd fallback
    | if token not sent in header or cookie
    */
    'input' => 'token',

    /*
    | claim in JWT, mapped to User identifier
    */
    'claim' => 'sub',

    /*
    | Model class provided to requests
    */
    'model' => 'App\User',

    /*
    | expiration time in seconds
    */
    'expires_in' => (60 * 60 * 24), // 24 hours

    /*
    | environment var that stores the key to sign tokens
    */
    'env_jwt_secret_key' => 'JWT_SIGN_SECRET',

    /*
    | guard, driver and provider unique names to use in auth
    | process, configurable to avoid collisions with other
    | configured guards, if guard is 'jwt' default, it will
    | allow middleware('auth:jwt') used as guard
    */
    'guard' => 'jwt',
    'driver' => 'jwt',
    'provider' => 'jwt',
    'policy' => function (Request $request, Authenticatable $user = null) {
        if(
            method_exists($user, 'hasPendingConfirmation') &&
            $user->hasPendingConfirmation()
        ) return null;
    },
];
