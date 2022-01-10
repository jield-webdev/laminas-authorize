<?php

declare(strict_types=1);

namespace Jield\Authorize\Rule;

use BjyAuthorize\Guard\AbstractGuard;
use BjyAuthorize\Guard\Route;
use Laminas\EventManager\EventManagerInterface;
use Laminas\Mvc\MvcEvent;

class RuleWithAssertion extends Route
{
    public function attach(EventManagerInterface $events, $priority = 1)
    {
        $this->listeners[] = $events->attach(MvcEvent::EVENT_ROUTE, [$this, 'onRoute'], -999);
    }

    public function onRoute(MvcEvent $event): void
    {
        //Grab the routeMatch from the event
        $routeMatch = $event->getRouteMatch()?->getMatchedRouteName();
        $action     = $event->getRouteMatch()?->getParam('action');
        $privilege  = $event->getRouteMatch()?->getParam('privilege');

        //Procude an equivalent assertion name
        $resource = $this->extractResourcesFromRule($resource);
        die(__CLASS__);

        //Try to see if we can find the assertion name in the list of rules
        $assertionClass = $this->rulesWithAssertions[$assertionName] ?? null;

        if (null !== $assertionClass) {
            //We only do allow rules
            if ($this->container->has($assertionClass)) {
                /** @var AbstractEntityAssertion|AbstractAssertion $assert */
                $assert = $this->container->get($assertionClass);

                if ($assert instanceof AbstractEntityAssertion) {
                    $assert->setRouteMatch($event->getRouteMatch());
                }
                print sprintf(
                    "Setting allow rule %s with privilege %s using assert %s",
                    $assertionName,
                    $privilege ?? $action,
                    $assertionClass
                );

                //Do not specify any roles, we do that in the assertion, giving a role would lead to ignorance of the assertion
                $this->acl->allow(
                    roles:     null,
                    resources: $assertionName,
                    assert:    $assert
                );
            } else {
                throw new \InvalidArgumentException(sprintf('Assertion class %s cannot be found', $assertionClass));
            }
        }
    }
}
