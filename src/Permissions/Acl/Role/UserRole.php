<?php

namespace JieldAuthorize\Permissions\Acl\Role;

use Contact\Entity\Contact;
use Laminas\Permissions\Acl\Role\RoleInterface;

class UserRole implements RoleInterface
{
    private ?Contact $contact;

    public function __construct(?Contact $contact)
    {
        $this->contact = $contact;
    }

    public function hasContact(): bool
    {
        return null !== $this->contact;
    }

    public function getContact(): Contact
    {
        if (null === $this->contact) {
            throw new \RuntimeException(
                'You are trying to get the contact, but no contact is set, are you logged in and did you check the isLoggedIn()'
            );
        }

        return $this->contact;
    }

    public function __toString()
    {
        return $this->getRoleId();
    }

    public function getRoleId(): string
    {
        if (null === $this->contact) {
            return 'guest';
        }

        return (string)$this->contact->getId();
    }
}
