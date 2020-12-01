<?php

declare(strict_types=1);

namespace App\EventListeners;

use Symfony\Component\Security\Http\Event\LoginSuccessEvent;

interface LoginSuccess extends EventListener
{
    public function __invoke(LoginSuccessEvent $event);
}
