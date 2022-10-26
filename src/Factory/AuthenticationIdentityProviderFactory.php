<?php

declare(strict_types=1);

namespace Jield\Authorize\Factory;

use Interop\Container\ContainerInterface;
use Jield\Authorize\Provider\Identity\AuthenticationIdentityProvider;
use Jield\Authorize\Service\AccessRolesByUserInterface;
use Jield\Authorize\Service\HasPermitInterface;
use Laminas\Authentication\AuthenticationService;
use Laminas\ServiceManager\Factory\FactoryInterface;
use Webmozart\Assert\Assert;

final class AuthenticationIdentityProviderFactory implements FactoryInterface
{
    public function __invoke(
        ContainerInterface $container,
        $requestedName,
        ?array $options = null
    ): AuthenticationIdentityProvider {
        $config = $container->get('config')['jield_authorize'] ?? [];

        if (!isset($config['access_service'])) {
            throw new \RuntimeException(
                sprintf(
                    'Service access_service implementing interface %s is missing',
                    AccessRolesByUserInterface::class
                )
            );
        }

        if (!isset($config['permit_service'])) {
            throw new \RuntimeException(
                sprintf(
                    'Service permit_service implementing interface %s is missing',
                    HasPermitInterface::class
                )
            );
        }

        //Check if the services have the correct interfaces
        Assert::implementsInterface($config['access_service'], AccessRolesByUserInterface::class);
        Assert::implementsInterface($config['permit_service'], HasPermitInterface::class);

        $dependencies = [
            $container->get(AuthenticationService::class),
            $container->get($config['access_service']),
            $container->get($config['permit_service']),
            $container->get('BjyAuthorize\Config')
        ];

        return new AuthenticationIdentityProvider(... $dependencies);
    }
}
