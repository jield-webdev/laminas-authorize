<?php

namespace Jield\Authorize\Service;

interface AccessRolesByUserInterface
{
    public function getAccessRolesByUser(UserAsRoleInterface $user): array;
}
