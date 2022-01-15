# jield-authorize

Small helper module to integrate BjyAuthorize (the kokspflanze/bjy-authorize fork) with dynamic assertions, which cannot
be serialized

Default config file

The access_service has to implement ```AccessRolesByUser``` interface and permit_service the ```HasPermitInterface```
the User class has to implement ```UserAsRoleInterface```

Make sure that 'BjyAuthorize' is enabled before 'Jield\Authorize' in module.config

```php
namespace BjyAuthorize;

use Admin\Entity\Role;
use Admin\Service\UserService;

return [
    'jield_authorize' => [
        'default_role'       => Role::ROLE_PUBLIC,
        'authenticated_role' => Role::ROLE_USER,
        'access_service'     => UserService::class,
        'permit_service'     => UserService::class,
        'cache_enabled'      => false,
        'role_entity_class'  => Role::class,
    ],
];
```