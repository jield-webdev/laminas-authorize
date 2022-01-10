<?php

declare(strict_types=1);

namespace JieldAutorize\Factory;

use Application\Service\AssertionService;
use BjyAuthorize\Service\Authorize;
use Interop\Container\ContainerInterface;
use Laminas\ServiceManager\Factory\FactoryInterface;

final class AssertionServiceFactory implements FactoryInterface
{
    public function __invoke(ContainerInterface $container, $requestedName, ?array $options = null): AssertionService
    {
        return new AssertionService($container);
    }
}
