<?php

declare(strict_types=1);

namespace Jield\Authorize\Rule;

use BjyAuthorize\Guard\Route;
use Jield\Authorize\Permissions\Acl\Assertion\AbstractAssertion;
use Jield\Authorize\Service\AuthorizeService;
use Laminas\EventManager\EventManagerInterface;
use Laminas\Mvc\MvcEvent;
use Laminas\Router\Http\RouteMatch;

class RuleWithAssertion extends Route
{
    public function attach(EventManagerInterface $events, $priority = 1)
    {
        $this->listeners[] = $events->attach(MvcEvent::EVENT_ROUTE, [$this, 'onRoute'], -999);
    }

    public function onRoute(MvcEvent $event): void
    {
        //Grab the routeMatch from the event
        $action    = $event->getRouteMatch()?->getParam('action');
        $privilege = $event->getRouteMatch()?->getParam('privilege');

        //Grab the ACL from the authorize service
        $acl = $event->getApplication()->getServiceManager()->get(AuthorizeService::class)->getAcl();

        //Procude an equivalent assertion name
        $resource = $this->extractResourceFromRouteMatch($event->getRouteMatch());

        //Try to see if we can find the assertion name in the list of rules
        $assertionClass = $this->rules[$resource]['assertion'] ?? null;

        if (null !== $assertionClass) {
            //We only do allow rules
            if ($this->container->has($assertionClass)) {
                /** @var AbstractAssertion $assert */
                $assert = $this->container->get($assertionClass);

                if ($assert instanceof AbstractAssertion) {
                    $assert->setRouteMatch($event->getRouteMatch());
                }
                print sprintf(
                    "Setting allow resource %s with privilege %s using assert %s",
                    $resource,
                    $privilege ?? $action,
                    $assertionClass
                );

                //Do not specify any roles, we do that in the assertion, giving a role would lead to ignorance of the assertion
                $acl->allow(
                    roles: null,
                    resources: $resource,
                    assert: $assert
                );
            } else {
                throw new \InvalidArgumentException(sprintf('Assertion class %s cannot be found', $assertionClass));
            }
        }
    }

    private function extractResourceFromRouteMatch(RouteMatch $routeMatch): string
    {
        return sprintf('route/%s', $routeMatch->getMatchedRouteName());
    }
}
