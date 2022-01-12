<?php

namespace Jield\Authorize;

use Jield\Authorize\Rule\RuleWithAssertion;
use Laminas\EventManager\EventInterface;
use Laminas\ModuleManager\Feature\BootstrapListenerInterface;
use Laminas\ModuleManager\Feature\ConfigProviderInterface;
use Laminas\Mvc\ApplicationInterface;
use Laminas\ServiceManager\AbstractFactory\ConfigAbstractFactory;
use Laminas\ServiceManager\ServiceManager;

class Module implements ConfigProviderInterface, BootstrapListenerInterface
{
    public function getConfig(): array
    {
        $configProvider = new ConfigProvider();

        return [
            'bjyauthorize'               => $configProvider->getBjyAuthorizeConfig(),
            ConfigAbstractFactory::class => $configProvider->getConfigAbstractFactory(),
            'service_manager'            => $configProvider->getDependencyConfig(),
        ];
    }

    public function onBootstrap(EventInterface $e): void
    {
        /** @var ApplicationInterface $app */
        $app = $e->getTarget();
        /** @var ServiceManager $serviceManager */
        $serviceManager = $app->getServiceManager();

        $ruleWithAssertion = $serviceManager->get(RuleWithAssertion::class);
        $ruleWithAssertion->attach($app->getEventManager());
    }
}
