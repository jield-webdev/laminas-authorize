<?php

namespace Jield\Authorize\Role;

use Laminas\ApiTools\MvcAuth\Identity\GuestIdentity;
use Laminas\Permissions\Acl\Role\RoleInterface;

class UserAsRole implements RoleInterface
{
    private null|UserAsRoleInterface|GuestIdentity $userAsRole;

    public function __construct(null|UserAsRoleInterface|GuestIdentity $userAsRole)
    {
        $this->userAsRole = $userAsRole;
    }

    public function hasLoggedinUser(): bool
    {
        return null !== $this->userAsRole;
    }

    public function getLoggedInUser(): UserAsRoleInterface
    {
        if (null === $this->userAsRole) {
            throw new \RuntimeException(
                'You are trying to get the logged in user, but no user is set, are you logged in and did you check the isLoggedIn()'
            );
        }

        return $this->userAsRole;
    }

    public function __toString()
    {
        return $this->getRoleId();
    }

    public function getRoleId(): string
    {
        if (!$this->userAsRole instanceof UserAsRoleInterface) {
            return 'guest';
        }

        return $this->userAsRole->getUserId();
    }
}
