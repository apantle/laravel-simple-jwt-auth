<?php

namespace Apantle\LaravelSimpleJwtAuth\Http\Middleware;

use Apantle\LaravelSimpleJwtAuth\JwtAuth;
use \Closure;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Symfony\Component\HttpFoundation\Cookie;
use Symfony\Component\HttpFoundation\Request as SymfonyRequest;

class RegenerateTokenCookieMiddleware
{
    /**
     * @param Request|SymfonyRequest $request
     * @param Closure $next
     */
    public function handle($request, Closure $next)
    {
        /** @var Response $response */
        $response = $next($request);

        if ($response->getStatusCode() >= Response::HTTP_BAD_REQUEST) return $response;

        /** @var Authenticatable $user */
        $user = $request->user();
        if (is_null($user)) return $response;

        $this->setTokenCookieForUser($user, $response);

        return $response;
    }

    /**
     * Set token cookie with parameters set in config
     * @param Authenticatable $user
     * @param Response $response
     */
    protected function setTokenCookieForUser(Authenticatable $user, Response $response)
    {
        $token = JwtAuth::getTokenFor($user);

        $expiresInMinutes = config('jwt-auth.expires_in') / 60;

        $response->cookie(
            config('jwt-auth.cookie'),
            $token,
            $expiresInMinutes,
            config('session.path'),
            config('session.domain'),
            config('session.secure'),
            config('session.http_only'),
            false, // raw
            config('session.same_site')
        );
    }
}
