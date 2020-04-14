<?php

namespace Apantle\LaravelSimpleJwtAuth;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Http\Request;
use ReallySimpleJWT\Exception\ValidateException;
use ReallySimpleJWT\Token;

class JwtAuthTokenService
{
    /** @var int */
    protected $expiresIn;

    /** @var string */
    protected $issuer;

    /** @var string */
    protected $secret;

    /** @var Request */
    protected $request;

    public function __construct(Request $request)
    {
        $this->expiresIn = config('jwt-auth.expires_in');
        $this->issuer = $request->getHost();
        $this->secret = env(config('jwt-auth.env_jwt_secret_key'), 'local');
    }

    /**
     * @param Authenticatable $user
     * @return string
     * @throws ValidateException
     */
    public function getTokenFor(Authenticatable $user): string
    {
        $userId = $user->getAuthIdentifier();

        return Token::builder()->setPayloadClaim('sub', $userId)
            ->setSecret($this->secret)
            ->setIssuer($this->issuer)
            ->setIssuedAt(time())
            ->setExpiration(time() + $this->expiresIn)
            ->build()
            ->getToken();
    }

    public function getAuthIdentifier(string $token): ?string
    {
        if (!$this->isValid($token)) {
            return null;
        }

        $userId = $this->getUserIdentifier($token);

        return is_null($userId) ? null : strval($userId);
    }

    protected function isValid(string $token): bool
    {
        if ($token === '') {
            return false;
        }

        try {
            $v = Token::validate($token, $this->secret);
        } catch (\Exception $e) {
            return false;
        }
        return $v;
    }

    protected function getUserIdentifier(string $token): ?string
    {
        $claims = Token::getPayload($token, $this->secret);
        $lookupClaim = config('jwt-auth.claim');

        return isset($claims[$lookupClaim]) ? $claims[$lookupClaim] : null;
    }
}
