<?php

declare(strict_types=1);

namespace Jield\Authorize\Provider\Identity;

use JetBrains\PhpStorm\Pure;
use Jield\Authorize\Role\UserAsRole;
use Laminas\Authentication\AuthenticationService;

final class AuthenticationIdentityProvider extends \BjyAuthorize\Provider\Identity\AuthenticationIdentityProvider
{
    public const ACCESS_PUBLIC       = 'public';
    public const ACCESS_AUTHETICATED = 'user';

    protected $defaultRole;
    protected $authenticatedRole;

    #[Pure] public function __construct(
        AuthenticationService $authService,
        array $authorizeConfig
    ) {
        parent::__construct($authService);

        $this->defaultRole       = $authorizeConfig['default_role'] ?? self::ACCESS_PUBLIC;
        $this->authenticatedRole = $authorizeConfig['authenticated_role'] ?? self::ACCESS_USER;
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

    public function getIdentityRoles(): array
    {
        if (!$this->authService->hasIdentity()) {
            return [$this->defaultRole];
        }

        return $this->adminService->findAccessRolesByContactAsArray($this->authService->getIdentity());
    }
}
