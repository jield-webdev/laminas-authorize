<?php

namespace JieldAuthorize;

use BjyAuthorize\Service\Authorize;
use JetBrains\PhpStorm\ArrayShape;
use JetBrains\PhpStorm\Pure;
use JieldAuthorize\Factory\AuthorizeServiceFactory;
use JieldAuthorize\Service\AssertionService;
use JieldAuthorize\Service\AuthorizeService;
use JieldAutorize\Factory\AssertionServiceFactory;

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
                AuthorizeService::class => AuthorizeServiceFactory::class,
                AssertionService::class => AssertionServiceFactory::class
            ],
        ];
    }
}
