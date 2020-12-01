<?php

declare(strict_types=1);

namespace App\Security;

use App\EventListeners\CheckPassport;
use Symfony\Component\Security\Core\Exception\CustomUserMessageAuthenticationException;
use Symfony\Component\Security\Http\Authenticator\Passport\UserPassportInterface;
use Symfony\Component\Security\Http\Event\CheckPassportEvent;
use Symfony\Component\Security\Http\Event\LogoutEvent;

final class DisallowBannedUsers implements CheckPassport
{
    public function __invoke(CheckPassportEvent $event)
    {
        $passport = $event->getPassport();

        if (!$passport instanceof UserPassportInterface) {
            throw new CustomUserMessageAuthenticationException('Invalid passport');
        }

        if ($passport->getUser()->getUsername() === 'bad_user@symfony.com') {
            throw new CustomUserMessageAuthenticationException('You are banned!');
        }
    }
}
