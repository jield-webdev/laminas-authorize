<?php

declare(strict_types=1);

namespace Jield\Authorize\Factory;

use Interop\Container\ContainerInterface;
use Jield\Authorize\Service\AssertionService;
use Jield\Authorize\Service\AuthorizeService;
use Laminas\ServiceManager\Factory\FactoryInterface;
use Psr\Container\ContainerExceptionInterface;
use Psr\Container\NotFoundExceptionInterface;

final class AssertionServiceFactory implements FactoryInterface
{
    /**
     * @throws ContainerExceptionInterface
     * @throws NotFoundExceptionInterface
     */
    public function __invoke(
        ContainerInterface $container,
        $requestedName,
        ?array $options = null
    ): AssertionService {
        return new AssertionService($container);
    }
}
