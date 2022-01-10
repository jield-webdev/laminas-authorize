<?php

namespace JieldAuthorize\Service;

use Application\Permissions\Acl\Assertion\AbstractAssertion;
use Application\Permissions\Acl\Assertion\AbstractEntityAssertion;
use Application\Permissions\Acl\Role\ContactRole;
use BjyAuthorize\Provider\Identity\ProviderInterface as IdentityProvider;
use BjyAuthorize\Service\Authorize;
use Interop\Container\ContainerInterface;
use Laminas\Cache\Exception\ExceptionInterface;
use Laminas\Cache\Storage\Adapter\Redis;
use Laminas\Cache\Storage\StorageInterface;
use Laminas\Mvc\MvcEvent;
use Laminas\Permissions\Acl\Acl;
use Psr\Container\ContainerExceptionInterface;
use Psr\Container\NotFoundExceptionInterface;

class AuthorizeService extends Authorize
{
    private array              $rulesWithAssertions = [];
    private Redis              $cache;
    private ContainerInterface $container;

    /**
     * @throws ContainerExceptionInterface
     * @throws NotFoundExceptionInterface
     */
    public function __construct(ContainerInterface $container)
    {
        $this->container = $container;
        /** @var StorageInterface $cache */
        $this->cache = $container->get('BjyAuthorize\Cache');
        parent::__construct($container->get('BjyAuthorize\Config'), $container);
    }

    /**
     * @throws NotFoundExceptionInterface
     * @throws ExceptionInterface
     * @throws ContainerExceptionInterface
     */
    public function load(): void
    {
        if (null === $this->loaded) {
            return;
        }

        $this->loaded = null;

        $aclKacheKey         = sprintf('%s_acl', $this->config['cache_key']);
        $rulesWithAssertions = sprintf('%s_rules_with_assertion', $this->config['cache_key']);

        $success      = false;
        $cacheEnabled = $this->config['cache_enabled'] ?? false;
        if ($cacheEnabled) {
            $this->rulesWithAssertions = $this->cache->getItem($rulesWithAssertions, $success) ?? [];
            $this->acl                 = $this->cache->getItem($aclKacheKey, $success);
        }

        if (!$this->acl instanceof Acl || !$success) {
            $this->loadAcl();
            if ($cacheEnabled) {
                $this->cache->setItem($aclKacheKey, $this->acl);
                $this->cache->setItem($rulesWithAssertions, $this->rulesWithAssertions);
            }
        }

        $this->setIdentityProvider($this->container->get(IdentityProvider::class));

        $parentRoles = $this->getIdentityProvider()->getIdentityRoles();

        $this->acl->addRole($this->getIdentity(), $parentRoles);
    }

    private function loadAcl(): void
    {
        $this->acl = new Acl();

        //Set the role provider first
        foreach ($this->container->get('BjyAuthorize\RoleProviders') as $provider) {
            $this->addRoleProvider($provider);
        }

        foreach ($this->roleProviders as $provider) {
            $this->addRoles($provider->getRoles());
        }

        foreach ($this->container->get('BjyAuthorize\Guards') as $guard) {
            $this->addGuard($guard);
        }

        foreach ($this->resourceProviders as $provider) {
            $this->loadResource($provider->getResources(), null);
        }

        foreach ($this->ruleProviders as $provider) {
            $rules = $provider->getRules();

            if (isset($rules['allow'])) {
                foreach ($rules['allow'] as $rule) {
                    $this->loadRule($rule, static::TYPE_ALLOW);
                }
            }
        }
    }

    protected function loadRule(array $rule, $type): void
    {
        $privileges = null;
        $ruleSize   = count($rule);

        if (4 === $ruleSize) {
            [$roles, $resources, $privileges, $assertion] = $rule;
            $this->rulesWithAssertions[$resources] = $assertion;
        } elseif (3 === $ruleSize) {
            [$roles, $resources, $privileges] = $rule;
        } elseif (2 === $ruleSize) {
            [$roles, $resources] = $rule;
        } else {
            throw new \InvalidArgumentException('Invalid rule definition: ' . print_r($rule, true));
        }

        //We only do allow rules
        $this->acl->allow($roles, $resources, $privileges);
    }

    public function getIdentity(): ContactRole
    {
        return $this->getIdentityProvider()->getIdentity();
    }

    public function loadRulesWithAssertions(MvcEvent $event): void
    {
        //Grab the routeMatch from the event
        $routeMatch = $event->getRouteMatch()?->getMatchedRouteName();
        $action     = $event->getRouteMatch()?->getParam('action');
        $privilege  = $event->getRouteMatch()?->getParam('privilege');

        //Procude an equivalent assertion name
        $assertionName = sprintf('route/%s', $routeMatch);

        //Try to see if we can find the assertion name in the list of rules
        $assertionClass = $this->rulesWithAssertions[$assertionName] ?? null;

        if (null !== $assertionClass) {
            //We only do allow rules
            if ($this->container->has($assertionClass)) {
                /** @var AbstractEntityAssertion|AbstractAssertion $assert */
                $assert = $this->container->get($assertionClass);

                if ($assert instanceof AbstractEntityAssertion) {
                    $assert->setRouteMatch($event->getRouteMatch());
                }
                print sprintf(
                    "Setting allow rule %s with privilege %s using assert %s",
                    $assertionName,
                    $privilege ?? $action,
                    $assertionClass
                );

                //Do not specify any roles, we do that in the assertion, giving a role would lead to ignorance of the assertion
                $this->acl->allow(
                    roles:     null,
                    resources: $assertionName,
                    assert:    $assert
                );
            } else {
                throw new \InvalidArgumentException(sprintf('Assertion class %s cannot be found', $assertionClass));
            }
        }
    }

    public function getIdentityRoles(): array
    {
        /** @var AuthenticationIdentityProvider $identityProvider */
        $identityProvider = $this->container->get(AuthenticationIdentityProvider::class);
        return $this->getIdentityProvider()->getIdentityRoles();
    }
}
