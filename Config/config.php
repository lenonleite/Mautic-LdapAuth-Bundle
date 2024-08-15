<?php

return [
    'name'        => 'LdapAuth',
    'description' => 'Enables LDAP authentication',
    'version'     => '1.0',
    'author'      => 'Monogramm',

    'services'    => [
        'events' => [
            'mautic.ldapauth.user.subscriber' => [
                'class'     => MauticPlugin\MauticLdapAuthBundle\EventListener\UserSubscriber::class,
                'arguments' => [
                    'mautic.helper.core_parameters',
                    'router',
                ],
            ],
            'mautic.ldapauth.config.subscriber' => [
                'class' => MauticPlugin\MauticLdapAuthBundle\EventListener\ConfigSubscriber::class,
            ],
        ],
        'forms'  => [
            'mautic.form.type.ldapconfig' => [
                'class'     => MauticPlugin\MauticLdapAuthBundle\Form\Type\ConfigType::class,
                'alias'     => 'ldapconfig',
                'arguments' => [
                    'mautic.helper.core_parameters',
                    'translator',
                ],
            ],
        ],
        'other' => [
            'mautic.ldapuser.provider' => [
                'class'     => MauticPlugin\MauticLdapAuthBundle\Security\Provider\LdapUserProvider::class,
                'arguments' => [
                    'mautic.user.repository',
                    'mautic.permission.repository',
                    'session',
                    'event_dispatcher',
                    'security.password_hasher',
                ],
            ],
        ],
        'integrations' => [
        ],
    ],
    'parameters' => [
        'ldap_auth_host'     => null,
        'ldap_auth_port'     => 389,
        'ldap_auth_version'  => 3,
        'ldap_auth_ssl'      => false,
        'ldap_auth_starttls' => true,
        // TODO Coming feature: Bind DN
        // 'ldap_auth_bind_dn' => 'cn=admin,dc=ldap,dc=company,dc=com',
        // 'ldap_auth_bind_passwd' => null,
        'ldap_auth_base_dn'                => null,
        'ldap_auth_user_query'             => '(objectclass=inetOrgPerson)',
        'ldap_auth_isactivedirectory'      => false,
        'ldap_auth_activedirectory_domain' => null,
        'ldap_auth_username_attribute'     => 'uid',
        'ldap_auth_email_attribute'        => 'mail',
        'ldap_auth_firstname_attribute'    => 'givenname',
        'ldap_auth_lastname_attribute'     => 'sn',
        'ldap_auth_fullname_attribute'     => 'displayname',
    ],
];
