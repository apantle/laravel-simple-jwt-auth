<?php

namespace Apantle\LaravelSimpleJwtAuth\Http\Middleware;

use Apantle\LaravelSimpleJwtAuth\JwtAuth;
use \Closure;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;
use Illuminate\Http\Response as LaravelResponse;
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

        $cookie = cookie(
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

        $response->headers->setCookie($cookie);
    }
}
