<?php

/*
 * You can place your custom package configuration in here.
 */
return [
    'cookie' => 'token',
    'claim' => 'sub',
    'expires_in' => (60 * 60 * 24), // 24 hours
    'env_jwt_secret_key' => 'JWT_SIGN_SECRET',
    'model' => 'App\Model\User',
    'guard' => 'jwt',
    'driver' => 'jwt',
    'provider' => 'jwt',
];
