<?php

namespace Jield\Authorize\Service;

use Jield\Authorize\Role\UserAsRoleInterface;

interface HasPermitInterface
{
    public function hasPermit(UserAsRoleInterface $user, object $resource, array|string $privilege): bool;
}
