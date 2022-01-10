<?php

declare(strict_types=1);

namespace JieldAuthorize\Service;

use Laminas\Permissions\Acl\Acl;
use Laminas\ServiceManager\ServiceManager;
use Psr\Container\ContainerExceptionInterface;
use Psr\Container\NotFoundExceptionInterface;

class AssertionService
{
    private Acl $acl;

    /**
     * @throws ContainerExceptionInterface
     * @throws NotFoundExceptionInterface
     */
    public function __construct(private ServiceManager $container)
    {
        /** @var AuthorizeService $authorizeService */
        $authorizeService = $this->container->get(AuthorizeService::class);
        $this->acl        = $authorizeService->getAcl();
    }

    /**
     * @throws ContainerExceptionInterface
     */
    public function addResource($entity, string $assertion): void
    {
        if (!$this->acl->hasResource($entity)) {
            $this->acl->addResource($entity);
            $this->acl->allow([], $entity, [], $this->container->build($assertion));
        }
    }
}
