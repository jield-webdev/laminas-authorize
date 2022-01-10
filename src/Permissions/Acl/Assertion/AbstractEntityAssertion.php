<?php

declare(strict_types=1);

namespace Application\Permissions\Acl\Assertion;

use Admin\Entity\Access;
use Admin\Service\AdminService;
use Application\Authentication\Provider\AuthenticationIdentityProvider;
use Application\Entity\AbstractEntity;
use Application\Permissions\Acl\Role\ContactRole;
use Contact\Entity\Contact;
use Contact\Service\ContactService;
use Interop\Container\ContainerInterface;
use JetBrains\PhpStorm\Pure;
use Laminas\Permissions\Acl\Assertion\AssertionInterface;
use Laminas\Router\Http\RouteMatch;

abstract class AbstractEntityAssertion implements AssertionInterface
{
    protected AdminService                   $adminService;
    protected ContactService                 $contactService;
    protected AuthenticationIdentityProvider $authenticationIdentityProvider;
    protected array                          $identityRoles;
    protected ContactRole                    $contactRole;
    protected ?string                        $privilege = null;
    protected RouteMatch                     $routeMatch;

    public function __construct(private ContainerInterface $container)
    {
        $this->contactService                 = $this->container->get(ContactService::class);
        $this->authenticationIdentityProvider = $this->container->get(AuthenticationIdentityProvider::class);
        $this->identityRoles                  = $this->authenticationIdentityProvider->getIdentityRoles();
        $this->contactRole                    = $this->authenticationIdentityProvider->getIdentity();
    }

    public function setRouteMatch(RouteMatch $routeMatch): AbstractEntityAssertion
    {
        $this->routeMatch = $routeMatch;
        return $this;
    }

    protected function hasPermit(AbstractEntity $entity, string|array $privilege): bool
    {
        return $this->contactService->contactHasPermit($this->getContact(), $privilege, $entity);
    }

    protected function getContact(): Contact
    {
        return $this->contactRole->getContact();
    }

    protected function parsePrivilege(?string $privilege): string
    {
        //Short circuit the function in case the privilege is known via the acl
        if (null !== $privilege) {
            return $privilege;
        }

        if (!isset($this->routeMatch)) {
            throw new \RuntimeException('Calling parsePrivige before setting the routematch is not possible');
        }

        return $this->routeMatch->getParam('privilege') ?? $this->routeMatch->getParam('action');
    }

    protected function contactHasAccessRoles(array|string $roles): bool
    {
        if (is_string($roles)) {
            $roles = [$roles];
        }

        if (empty($roles)) {
            return true;
        }

        //Public has always access
        if (in_array(Access::ACCESS_PUBLIC, $roles, true)) {
            return true;
        }

        return !empty(array_intersect($roles, $this->authenticationIdentityProvider->getIdentityRoles()));
    }

    #[Pure] protected function isLoggedIn(): bool
    {
        return $this->contactRole->hasContact();
    }

}
