<?php

declare(strict_types=1);

namespace Jield\Authorize\Rule;

use BjyAuthorize\Guard\Route;
use Jield\Authorize\Permissions\Acl\Assertion\AbstractAssertion;
use Jield\Authorize\Service\AuthorizeService;
use Laminas\EventManager\EventManagerInterface;
use Laminas\Mvc\MvcEvent;

class RulesWithAssertion extends Route
{
    public function attach(EventManagerInterface $events, $priority = -999)
    {
        $this->listeners[] = $events->attach(MvcEvent::EVENT_ROUTE, [$this, 'onRoute'], $priority);
    }

    public function onRoute(MvcEvent $event): void
    {
        //Grab the ACL from the authorize service
        $acl = $event->getApplication()->getServiceManager()->get(AuthorizeService::class)->getAcl();

        foreach ($this->rules as $resource => $rule) {
            if (isset($rule['assertion'])) {
                $assertionClass = $rule['assertion'];
                if ($this->container->has($assertionClass)) {
                    /** @var AbstractAssertion $assert */
                    $assert = $this->container->get($assertionClass);

                    if ($assert instanceof AbstractAssertion) {
                        $assert->setRouteMatch($event->getRouteMatch());
                    }

                    //Do not specify any roles, we do that in the assertion, giving a role would lead to ignorance of the assertion
                    $acl->allow(
                        roles:     null,
                        resources: $resource,
                        assert:    $assert
                    );
                } else {
                    throw new \InvalidArgumentException(sprintf('Assertion class %s cannot be found', $assertionClass));
                }
            }
        }
    }
}
