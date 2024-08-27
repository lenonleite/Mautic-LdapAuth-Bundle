<?php

namespace MauticPlugin\MauticLdapAuthBundle\EventListener;

use Mautic\ConfigBundle\ConfigEvents;
use Mautic\ConfigBundle\Event\ConfigBuilderEvent;
use Mautic\ConfigBundle\Event\ConfigEvent;
use MauticPlugin\MauticLdapAuthBundle\Form\Type\ConfigType;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;

/**
 * Class ConfigSubscriber.
 */
class ConfigSubscriber implements EventSubscriberInterface
{
    public static function getSubscribedEvents(): array
    {
        return [
            ConfigEvents::CONFIG_ON_GENERATE => ['onConfigGenerate', 0],
            ConfigEvents::CONFIG_PRE_SAVE    => ['onConfigSave', 0],
        ];
    }

    public function onConfigGenerate(ConfigBuilderEvent $event): void
    {
        $event->addForm(
            [
                'bundle'     => 'MauticLdapAuthBundle',
                'formAlias'  => 'ldapconfig',
                'formType'   => ConfigType::class,
                'formTheme'  => '@MauticLdapAuth/FormTheme/Config/_config_ldapconfig_widget.html.twig',
                'parameters' => $event->getParametersFromConfig('MauticLdapAuthBundle'),
            ]
        );
    }

    public function onConfigSave(ConfigEvent $event)
    {
        $data = $event->getConfig('ldapconfig');

        // Manipulate the values
        if (!empty($data['ldap_auth_host']) && 'ldaps://' === substr($data['ldap_auth_host'], 0, 8)) {
            $data['ldap_auth_ssl'] = true;
        }

        $event->setConfig($data, 'ldapconfig');
    }
}
