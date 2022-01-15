<?php

namespace Jield\Authorize;

use BjyAuthorize\Provider\Role\ObjectRepositoryProvider;
use BjyAuthorize\Service\Authorize;
use Doctrine\ORM\EntityManager;
use Jield\Authorize\Factory\AssertionServiceFactory;
use Jield\Authorize\Factory\AuthenticationIdentityProviderFactory;
use Jield\Authorize\Factory\AuthorizeServiceFactory;
use Jield\Authorize\Factory\ConfigServiceFactory;
use Jield\Authorize\Factory\RuleWithAssertionFactory;
use Jield\Authorize\Provider\Identity\AuthenticationIdentityProvider;
use Jield\Authorize\Rule\RulesWithAssertion;
use Jield\Authorize\Service\AssertionService;
use Jield\Authorize\Service\AuthorizeService;
use Jield\Authorize\View\UnauthorizedStrategy;
use Laminas\Authentication\AuthenticationService;
use Laminas\ServiceManager\AbstractFactory\ConfigAbstractFactory;

class ConfigProvider
{
    public function __invoke(): array
    {
        return [
            'dependencies' => $this->getDependencyConfig(),
        ];
    }

    public function getDependencyConfig(): array
    {
        return [
            'aliases'   => [
                Authorize::class => AuthorizeService::class
            ],
            'factories' => [
                'BjyAuthorize\Config'                 => ConfigServiceFactory::class,
                UnauthorizedStrategy::class           => ConfigAbstractFactory::class,
                AuthorizeService::class               => AuthorizeServiceFactory::class,
                AssertionService::class               => AssertionServiceFactory::class,
                AuthenticationIdentityProvider::class => AuthenticationIdentityProviderFactory::class,
                RulesWithAssertion::class             => RuleWithAssertionFactory::class
            ],
        ];
    }

    public function getConfigAbstractFactory(): array
    {
        return [
            UnauthorizedStrategy::class => [
                AuthenticationService::class,
                'BjyAuthorize\Config'
            ]
        ];
    }

    public function getBjyAuthorizeConfig(): array
    {
        return [
            'identity_provider'     => AuthenticationIdentityProvider::class,
            'unauthorized_strategy' => UnauthorizedStrategy::class,
            'cache_enabled'         => true,
            'role_providers'        => [
                ObjectRepositoryProvider::class => [
                    'object_manager'    => EntityManager::class,
                    'role_entity_class' => 'Class',
                ],
            ],
        ];
    }
}
