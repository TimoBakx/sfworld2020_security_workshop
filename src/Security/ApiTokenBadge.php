<?php

declare(strict_types=1);

namespace App\Security;

use App\Entity\ApiToken;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\BadgeInterface;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;

final class ApiTokenBadge implements BadgeInterface
{
    /**
     * @var ApiToken
     */
    private $token;

    public function __construct(string $token, callable $loader)
    {
        $this->token = $loader($token);
    }

    public function toUserBadge(): UserBadge
    {
        return new UserBadge(
            $this->token->getToken(),
            function ($token) {
                if ($token === $this->token->getToken()) {
                    return $this->token->getUser();
                }
                return null;
            }
        );
    }

    /**
     * @return string[]
     */
    public function getScopeRoles(): array
    {
        $roles = [];
        foreach ($this->token->getScopes() as $scope) {
            $roles[] = sprintf('ROLE_SCOPE_%s', \strtoupper($scope));
        }
        return $roles;
    }

    public function isResolved(): bool
    {
        return true;
    }
}
