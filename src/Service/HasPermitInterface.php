<?php

namespace Jield\Authorize\Service;

use Jield\Authorize\Role\UserAsRole;

interface HasPermitInterface
{
    public function hasPermit(UserAsRole $userAsRole, object $resource, array|string $privilege): bool;
}
