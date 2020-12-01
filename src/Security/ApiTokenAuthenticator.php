<?php

declare(strict_types=1);

namespace App\Security;

use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Http\Authenticator\AuthenticatorInterface;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\PassportInterface;
use Symfony\Component\Security\Http\Authenticator\Passport\SelfValidatingPassport;
use Symfony\Component\Security\Http\Authenticator\Passport\UserPassportInterface;
use Symfony\Component\Security\Http\Authenticator\Token\PostAuthenticationToken;

final class ApiTokenAuthenticator implements AuthenticatorInterface
{
    const HEADER = 'X-TOKEN';

    /**
     * @var ApiTokenUserLoader
     */
    private $loader;

    public function __construct(ApiTokenUserLoader $loader)
    {
        $this->loader = $loader;
    }

    public function supports(Request $request): ?bool
    {
        return $request->headers->has(self::HEADER);
    }

    public function authenticate(Request $request): PassportInterface
    {
        $token = $request->headers->get(self::HEADER);

        return new SelfValidatingPassport(
            new UserBadge($token, $this->loader)
        );
    }

    public function createAuthenticatedToken(PassportInterface $passport, string $firewallName): TokenInterface
    {
        if (!$passport instanceof UserPassportInterface) {
            throw new \LogicException(sprintf(
                'Invalid passport type, "%s" needs to implement %s',
                \get_class($passport),
                UserPassportInterface::class
            ));
        }

        return new PostAuthenticationToken(
            $passport->getUser(),
            $firewallName,
            $passport->getUser()->getRoles()
        );
    }

    public function onAuthenticationSuccess(Request $request, TokenInterface $token, string $firewallName): ?Response
    {
        return null;
        return new JsonResponse(['email' => $token->getUsername(), 'roles' => $token->getRoleNames()]);
    }

    public function onAuthenticationFailure(Request $request, AuthenticationException $exception): ?Response
    {
        return new JsonResponse(['error' => $exception->getMessageKey()], 401);
    }
}
