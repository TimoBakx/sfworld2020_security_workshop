<?php

declare(strict_types=1);

namespace App\EventListeners;

use Symfony\Component\Security\Http\Event\CheckPassportEvent;

interface CheckPassport extends EventListener
{
    public function __invoke(CheckPassportEvent $event);
}
