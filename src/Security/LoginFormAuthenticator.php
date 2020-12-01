<?php

declare(strict_types=1);

namespace App\Security;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Http\Authenticator\AuthenticatorInterface;
use Symfony\Component\Security\Http\Authenticator\Passport\PassportInterface;

final class LoginFormAuthenticator implements AuthenticatorInterface
{
    public function supports(Request $request): ?bool
    {
        return $request->isMethod(Request::METHOD_POST)
            && $request->attributes->get('_route') === 'app_login';
    }

    public function authenticate(Request $request): PassportInterface
    {
        // TODO: Implement authenticate() method.
    }

    public function createAuthenticatedToken(PassportInterface $passport, string $firewallName): TokenInterface
    {
        // TODO: Implement createAuthenticatedToken() method.
    }

    public function onAuthenticationSuccess(Request $request, TokenInterface $token, string $firewallName): ?Response
    {
        // TODO: Implement onAuthenticationSuccess() method.
    }

    public function onAuthenticationFailure(Request $request, AuthenticationException $exception): ?Response
    {
        // TODO: Implement onAuthenticationFailure() method.
    }
}
