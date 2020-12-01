<?php

declare(strict_types=1);

namespace App\Security;

use App\Entity\ApiToken;
use App\Entity\User;
use App\Repository\ApiTokenRepository;
use Symfony\Component\Security\Core\Exception\BadCredentialsException;

final class ApiTokenUserLoader
{
    /**
     * @var ApiTokenRepository
     */
    private $repository;

    public function __construct(ApiTokenRepository $repository)
    {
        $this->repository = $repository;
    }

    public function __invoke(string $apiToken): User
    {
        $token = $this->repository->findOneBy(['token' => $apiToken]);

        if (!$token instanceof ApiToken) {
            throw new BadCredentialsException();
        }

        return $token->getUser();
    }
}
