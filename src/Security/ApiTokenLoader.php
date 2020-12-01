<?php

declare(strict_types=1);

namespace App\Security;

use App\Entity\ApiToken;
use App\Repository\ApiTokenRepository;
use Symfony\Component\Security\Core\Exception\BadCredentialsException;

final class ApiTokenLoader
{
    /**
     * @var ApiTokenRepository
     */
    private $repository;

    public function __construct(ApiTokenRepository $repository)
    {
        $this->repository = $repository;
    }

    public function __invoke(string $apiToken): ApiToken
    {
        $token = $this->repository->findOneBy(['token' => $apiToken]);

        if (!$token instanceof ApiToken) {
            throw new BadCredentialsException();
        }

        return $token;
    }
}
