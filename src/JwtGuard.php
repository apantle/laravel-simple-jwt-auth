<?php

namespace Apantle\LaravelSimpleJwtAuth;

use Illuminate\Auth\GuardHelpers;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\Guard;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\Request;

class JwtGuard implements Guard
{
    use GuardHelpers;

    /** @var UserProvider */
    protected $provider;

    /** @var Request */
    protected $request;

    /** @var Model|Authenticatable */
    protected $user;

    /** @var JwtAuthTokenService */
    protected $tokenService;

    /**
     * JwtGuard constructor.
     * @param UserProvider $provider
     * @param Request $request
     * @param JwtAuthTokenService $tokenService
     */
    public function __construct(
        UserProvider $provider,
        Request $request,
        JwtAuthTokenService $tokenService
    ) {
        $this->provider = $provider;
        $this->request = $request;
        $this->tokenService = $tokenService;
    }

    public function user()
    {
        if (!is_null($this->user)) {
            return $this->user;
        }

        $token = $this->getPosibleToken($this->request);

        $userId = $this->tokenService->getAuthIdentifier($token);

        $this->user = $this->provider->retrieveById($userId);

        return $this->user;
    }

    public function validate(array $credentials = [])
    {
        return true;
    }

    /**
     * @param Request $request
     * @return string $token
     */
    protected function getPosibleToken(Request $request)
    {
        $token = $this->request->bearerToken();

        if (!empty($token)) {
            return $token;
        }

        if ($request->hasCookie('token')) {
            return $request->cookies->get('token');
        }

        return '';
    }
}
