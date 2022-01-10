<?php

declare(strict_types=1);

namespace Application\Permissions\Acl\Assertion;

use Admin\Entity\Access;
use Admin\Service\AdminService;
use Contact\Entity\Contact;
use Doctrine\ORM\PersistentCollection;
use Interop\Container\ContainerInterface;
use Laminas\Authentication\AuthenticationService;
use Laminas\Http\Request;
use Laminas\Permissions\Acl\Assertion\AssertionInterface;
use Laminas\Router\Http\RouteMatch;

use function count;
use function in_array;
use function is_array;
use function str_contains;
use function strtolower;

abstract class AbstractAssertion implements AssertionInterface
{
    protected AdminService       $adminService;
    protected ?Contact           $contact   = null;
    protected ?string            $privilege = null;
    protected RouteMatch         $routeMatch;
    protected ContainerInterface $container;

    public function __construct(ContainerInterface $container)
    {
        $this->container    = $container;
        $this->adminService = $container->get(AdminService::class);
        $this->contact      = $container->get(AuthenticationService::class)->getIdentity();
    }

    public function routeHasString(string $string): bool
    {
        return $this->hasRouteMatch() && str_contains($this->getRouteMatch()->getMatchedRouteName(), $string);
    }

    public function hasRouteMatch(): bool
    {
        return null !== $this->getRouteMatch()->getMatchedRouteName();
    }

    protected function getRouteMatch(): RouteMatch
    {
        $routeMatch = $this->container->get('Application')->getMvcEvent()->getRouteMatch();

        if (null !== $routeMatch) {
            return $routeMatch;
        }
        return new RouteMatch([]);
    }

    public function getPrivilege(): string
    {
        /**
         * When the privilege is_null (not given by the isAllowed helper), get it from the routeMatch
         */
        if (null === $this->privilege) {
            $this->privilege = $this->getRouteMatch()->getParam(
                'privilege',
                $this->getRouteMatch()->getParam('action')
            );
        }

        return $this->privilege;
    }

    public function setPrivilege(?string $privilege): AbstractAssertion
    {
        $this->privilege = $privilege;

        return $this;
    }

    public function getId(): ?int
    {
        if (null !== $this->getRequest()->getPost('id')) {
            return (int)$this->getRequest()->getPost('id');
        }
        if (!$this->hasRouteMatch()) {
            return null;
        }
        if (null !== $this->getRouteMatch()->getParam('id')) {
            return (int)$this->getRouteMatch()->getParam('id');
        }

        return null;
    }

    protected function getRequest(): Request
    {
        $request = $this->container->get('Application')->getMvcEvent()->getRequest();

        if (null !== $request) {
            return $request;
        }
        return new Request();
    }

    public function rolesHaveAccess($accessRoleOrCollection): bool
    {
        $accessRoles = $this->prepareAccessRoles($accessRoleOrCollection);
        if (count($accessRoles) === 0) {
            return true;
        }

        foreach ($accessRoles as $access) {
            if ($access === strtolower(Access::ACCESS_PUBLIC)) {
                return true;
            }
            if (
                $this->hasContact()
                && in_array(
                    $access,
                    $this->adminService->findAccessRolesByContactAsArray($this->contact),
                    true
                )
            ) {
                return true;
            }
        }

        return false;
    }

    private function prepareAccessRoles($accessRoleOrCollection): array
    {
        if (!$accessRoleOrCollection instanceof PersistentCollection) {
            /*
             * We only have a string or array, so we need to lookup the role
             */
            if (is_array($accessRoleOrCollection)) {
                foreach ($accessRoleOrCollection as $key => $accessItem) {
                    if (!$accessItem instanceof Access) {
                        $accessItem = $this->adminService->findAccessByName($accessItem);
                    }

                    if (null !== $accessItem) {
                        $accessRoleOrCollection[$key] = strtolower($accessItem->getAccess());
                    } else {
                        unset($accessRoleOrCollection[$key]);
                    }
                }
            } else {
                $accessRoleOrCollection = [
                    strtolower($this->adminService->findAccessByName($accessRoleOrCollection)->getAccess()),
                ];
            }
        }

        if ($accessRoleOrCollection instanceof PersistentCollection) {
            $accessRoleOrCollection = $accessRoleOrCollection->map(static function (Access $access) {
                return strtolower($access->getAccess());
            })->toArray();
        }

        return $accessRoleOrCollection;
    }

    public function hasContact(): bool
    {
        return null !== $this->contact;
    }
}
