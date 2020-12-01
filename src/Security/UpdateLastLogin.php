<?php

declare(strict_types=1);

namespace App\Security;

use App\Entity\User;
use App\EventListeners\LoginSuccess;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Component\Security\Http\Event\LoginSuccessEvent;

final class UpdateLastLogin implements LoginSuccess
{
    /**
     * @var EntityManagerInterface
     */
    private $entityManager;

    public function __construct(EntityManagerInterface $entityManager)
    {
        $this->entityManager = $entityManager;
    }

    public function __invoke(LoginSuccessEvent $event)
    {
        $user = $event->getUser();

        if ($user instanceof User) {
            $user->setLastLoginAt(new \DateTimeImmutable());

            $this->entityManager->persist($user);
            $this->entityManager->flush();
        }
    }
}
