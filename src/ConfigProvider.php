<?php

namespace Jield\Authorize;

use BjyAuthorize\Service\Authorize;
use BjyAuthorize\Service\RouteGuardServiceFactory;
use JetBrains\PhpStorm\ArrayShape;
use JetBrains\PhpStorm\Pure;
use Jield\Authorize\Factory\AssertionServiceFactory;
use Jield\Authorize\Factory\AuthenticationIdentityProviderFactory;
use Jield\Authorize\Factory\AuthorizeServiceFactory;
use Jield\Authorize\Factory\ConfigServiceFactory;
use Jield\Authorize\Provider\Identity\AuthenticationIdentityProvider;
use Jield\Authorize\Rule\RuleWithAssertion;
use Jield\Authorize\Service\AssertionService;
use Jield\Authorize\Service\AuthorizeService;
use Jield\Authorize\View\UnauthorizedStrategy;
use Laminas\Authentication\AuthenticationService;
use Laminas\ServiceManager\AbstractFactory\ConfigAbstractFactory;

class ConfigProvider
{
    #[Pure] #[ArrayShape(['dependencies' => "\string[][]"])] public function __invoke(): array
    {
        return [
            'dependencies' => $this->getDependencyConfig(),
        ];
    }

    #[ArrayShape(['factories' => "string[]", "aliases" => "string[]"])] public function getDependencyConfig(): array
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
                RuleWithAssertion::class              => RouteGuardServiceFactory::class
            ],
        ];
    }

    #[ArrayShape([
        AuthenticationIdentityProvider::class => "string[]",
        UnauthorizedStrategy::class           => "string[]"
    ])] public function getConfigAbstractFactory(): array
    {
        return [
            UnauthorizedStrategy::class => [
                AuthenticationService::class,
                'BjyAuthorize\Config'
            ]
        ];
    }

    #[ArrayShape([
        'identity_provider'     => "string",
        'unauthorized_strategy' => "string",
        'cache_enabled'         => "bool",
        'role_providers'        => "\string[][]"
    ])] public function getBjyAuthorizeConfig(): array
    {
        return [
            'identity_provider'     => AuthenticationIdentityProvider::class,
            'unauthorized_strategy' => UnauthorizedStrategy::class,
            'cache_enabled'         => true,
            'role_providers'        => [
                ObjectRepositoryProvider::class => [
                    'object_manager'    => EntityManager::class,
                    'role_entity_class' => Access::class,
                ],
            ],
        ];
    }
}
