<?php

namespace Apantle\LaravelSimpleJwtAuth;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Facades\Facade;

/**
 * @see \Apantle\LaravelSimpleJwtAuth\JwtAuthTokenService
 * @method static string getTokenFor(Authenticatable $user)
 * @method static string|null getAuthIdentifier(string $token)
 */
class JwtAuth extends Facade
{
    /**
     * Get the registered name of the component.
     *
     * @return string
     */
    protected static function getFacadeAccessor()
    {
        return 'jwt-auth';
    }
}
