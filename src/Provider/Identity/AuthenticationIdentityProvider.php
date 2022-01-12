<?php

declare(strict_types=1);

namespace Jield\Authorize\Provider\Identity;

use JetBrains\PhpStorm\Pure;
use Jield\Authorize\Role\UserAsRole;
use Jield\Authorize\Service\AccessRolesByUserInterface;
use Jield\Authorize\Service\HasPermitInterface;
use Laminas\Authentication\AuthenticationService;
use Laminas\Permissions\Acl\Role\RoleInterface;

final class AuthenticationIdentityProvider extends \BjyAuthorize\Provider\Identity\AuthenticationIdentityProvider
{
    public const ACCESS_PUBLIC       = 'public';
    public const ACCESS_AUTHETICATED = 'user';

    protected $defaultRole;
    protected $authenticatedRole;

    #[Pure] public function __construct(
        AuthenticationService $authService,
        private AccessRolesByUserInterface $accessOrUserService,
        private HasPermitInterface $permitService,
        array $authorizeConfig
    ) {
        parent::__construct($authService);

        $this->defaultRole       = $authorizeConfig['default_role'] ?? self::ACCESS_PUBLIC;
        $this->authenticatedRole = $authorizeConfig['authenticated_role'] ?? self::ACCESS_AUTHETICATED;
    }

    public function getIdentity(): UserAsRole
    {
        if (!$this->authService->hasIdentity()) {
            return new UserAsRole(null);
        }

        return new UserAsRole($this->authService->getIdentity());
    }

    public function hasIdentity(): bool
    {
        return $this->authService->hasIdentity();
    }

    public function rolesHaveAccess(string|array $roles): bool
    {
        if (!is_array($roles)) {
            $roles = [$roles];
        }

        return !empty(array_intersect($roles, $this->getIdentityRoles()));
    }

    public function getIdentityRoles(): array
    {
        if (!$this->authService->hasIdentity()) {
            return [$this->defaultRole];
        }

        return $this->accessOrUserService->getAccessRolesByUser($this->authService->getIdentity());
    }

    public function hasPermit(object $resource, string|array $privilege): bool
    {
        return $this->permitService->hasPermit($this->authService->getIdentity(), $resource, $privilege);
    }

    public function hasRole(string|array|Collection $roles): bool
    {
        if ($roles instanceof Collection) {
            $roles = $roles->map(fn(RoleInterface $role) => $role->getRoleId())->toArray();
        }

        if (!is_array($roles)) {
            $roles = [$roles];
        }

        return !empty(array_intersect($roles, $this->getIdentityRoles()));
    }
}
