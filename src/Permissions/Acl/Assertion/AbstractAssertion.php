<?php

declare(strict_types=1);

namespace Jield\Authorize\Permissions\Acl\Assertion;

use Interop\Container\ContainerInterface;
use Jield\Authorize\Provider\Identity\AuthenticationIdentityProvider;
use Jield\Authorize\Role\UserAsRole;
use Laminas\Permissions\Acl\Assertion\AssertionInterface;
use Laminas\Router\RouteMatch;
use phpDocumentor\Reflection\Types\Collection;

abstract class AbstractAssertion implements AssertionInterface
{
    protected AuthenticationIdentityProvider $authenticationIdentityProvider;
    protected UserAsRole $userAsRole;
    protected RouteMatch $routeMatch;

    public function __construct(protected ContainerInterface $container)
    {
        $this->authenticationIdentityProvider = $this->container->get(AuthenticationIdentityProvider::class);
    }

    public function setRouteMatch(RouteMatch $routeMatch): AbstractAssertion
    {
        $this->routeMatch = $routeMatch;
        return $this;
    }

    protected function hasPermit($entity, string|array $privilege): bool
    {
        return $this->authenticationIdentityProvider->hasPermit($entity, $privilege);
    }

    protected function hasRole(string|array|Collection $roles): bool
    {
        return $this->authenticationIdentityProvider->hasRole(roles: $roles);
    }

    protected function parsePrivilege(?string $privilege): string
    {
        //Short circuit the function in case the privilege is known via the acl
        if (null !== $privilege) {
            return $privilege;
        }

        if (!isset($this->routeMatch)) {
            throw new \RuntimeException('Calling parsePrivilege before setting the routematch is not possible');
        }

        return $this->routeMatch->getParam('privilege') ?? $this->routeMatch->getParam('action');
    }

    protected function isLoggedIn(): bool
    {
        return $this->authenticationIdentityProvider->hasIdentity();
    }
}
