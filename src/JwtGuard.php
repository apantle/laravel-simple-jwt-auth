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

        logger(__METHOD__, compact('token', 'userId'));

        $this->user = $this->evaluatePolicy(
            $this->provider->retrieveById($userId)
        );

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

        $cookieLookupKey = config('jwt-auth.cookie');
        if ($request->hasCookie($cookieLookupKey)) {
            return $request->cookies->get($cookieLookupKey);
        }

        $inputLookupKey = config('jwt-auth.input');
        if ($request->request->has($inputLookupKey) ||
            $request->query->has($inputLookupKey)
        ) {
            return $request->input($inputLookupKey, '');
        }

        return '';
    }

    protected function evaluatePolicy($user = null): ?Authenticatable
    {
        return call_user_func_array(
            config('jwt-auth.policy'),
            [$this->request, $user]
        );
    }

    public function viaRemember()
    {
        logger(__METHOD__);
        return false;
    }

    public function logout()
    {
        logger(__METHOD__);
    }

    public function logoutCurrentDevice()
    {
        logger(__METHOD__);
    }
}
