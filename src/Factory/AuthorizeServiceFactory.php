<?php

declare(strict_types=1);

namespace JieldAuthorize\Factory;

use Interop\Container\ContainerInterface;
use JieldAuthorize\Service\AuthorizeService;
use Laminas\ServiceManager\Factory\FactoryInterface;
use Psr\Container\ContainerExceptionInterface;
use Psr\Container\NotFoundExceptionInterface;

final class AuthorizeServiceFactory implements FactoryInterface
{
    /**
     * @throws ContainerExceptionInterface
     * @throws NotFoundExceptionInterface
     */
    public function __invoke(
        ContainerInterface $container,
        $requestedName,
        ?array $options = null
    ): AuthorizeService {
        return new AuthorizeService($container);
    }
}
