<?php

declare(strict_types=1);

namespace Jield\Authorize\Factory;

use BjyAuthorize\Guard\Route;
use Interop\Container\ContainerInterface;
use Jield\Authorize\Rule\RuleWithAssertion;
use Laminas\ServiceManager\Factory\FactoryInterface;

class RuleWithAssertionFactory implements FactoryInterface
{
    public function __invoke(ContainerInterface $container, $requestedName, ?array $options = null): RuleWithAssertion
    {
        return new RuleWithAssertion($container->get('BjyAuthorize\Config')['guards'][Route::class], $container);
    }
}
