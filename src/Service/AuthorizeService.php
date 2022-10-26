<?php

namespace Jield\Authorize\Service;

use BjyAuthorize\Service\Authorize;
use Interop\Container\ContainerInterface;
use Jield\Authorize\Provider\Identity\AuthenticationIdentityProvider;
use Jield\Authorize\Role\UserAsRole;
use Laminas\Cache\Exception\ExceptionInterface;
use Laminas\Cache\Storage\Adapter\Redis;
use Laminas\Cache\Storage\StorageInterface;
use Laminas\Permissions\Acl\Acl;
use Psr\Container\ContainerExceptionInterface;
use Psr\Container\NotFoundExceptionInterface;

class AuthorizeService extends Authorize
{
    private array                          $rulesWithAssertions = [];
    private Redis                          $cache;
    private ContainerInterface             $container;
    private AuthenticationIdentityProvider $authenticationIdentityProvider;

    /**
     * @throws ContainerExceptionInterface
     * @throws NotFoundExceptionInterface
     */
    public function __construct(ContainerInterface $container)
    {
        $this->container                      = $container;
        $this->authenticationIdentityProvider = $container->get(AuthenticationIdentityProvider::class);
        parent::__construct($container->get('BjyAuthorize\Config'), $container);

        $cacheEnabled = $this->config['cache_enabled'] ?? false;
        if ($cacheEnabled) {
            /** @var StorageInterface $cache */
            $this->cache = $container->get('BjyAuthorize\Cache');
        }
    }

    /**
     * @throws ExceptionInterface
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

        //$this->setIdentityProvider($this->authenticationIdentityProvider);
        $parentRoles = $this->authenticationIdentityProvider->getIdentityRoles();

        $this->acl->addRole($this->getIdentityAsRole(), $parentRoles);
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

    public function getIdentityAsRole(): UserAsRole
    {
        return $this->authenticationIdentityProvider->getIdentityAsRole();
    }

    /**
     * This function is very important and overrides the deefault "bjyauhorize-dentity
     * @return UserAsRole|string
     */
    public function getIdentity()
    {
        return $this->authenticationIdentityProvider->getIdentityAsRole();
    }

    public function getIdentityRoles(): array
    {
        return $this->authenticationIdentityProvider->getIdentityRoles();
    }
}
