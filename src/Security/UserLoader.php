<?php

declare(strict_types=1);

namespace App\Security;

use App\Entity\User;
use App\Repository\UserRepository;
use Symfony\Component\Security\Core\Exception\BadCredentialsException;

final class UserLoader
{
    /**
     * @var UserRepository
     */
    private $repository;

    public function __construct(UserRepository $repository)
    {
        $this->repository = $repository;
    }

    public function __invoke(string $email): User
    {
        $user = $this->repository->findOneBy(['email' => $email]);

        if (!$user instanceof User) {
            throw new BadCredentialsException();
        }

        return $user;
    }
}
