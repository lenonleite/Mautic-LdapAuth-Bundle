<?php

declare(strict_types=1);

use Mautic\CoreBundle\DependencyInjection\MauticCoreExtension;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;

return function (ContainerConfigurator $configurator): void {
    $services = $configurator->services()
        ->defaults()
        ->autowire()
        ->autoconfigure()
        ->public();

    $excludes = [
    ];

        $services->load('MauticPlugin\\MauticLdapAuthBundle\\', '../')
            ->exclude('../{'.implode(',', MauticCoreExtension::DEFAULT_EXCLUDES).'}')
            ->alias('mautic.integration.ldapauth', MauticPlugin\MauticLdapAuthBundle\Integration\LdapAuthIntegration::class)
            ->alias('mautic.integration.ldapformauth', MauticPlugin\MauticLdapAuthBundle\Integration\LdapFormAuthIntegration::class);
    //        ->exclude('../{'.implode(',', array_merge(MauticCoreExtension::DEFAULT_EXCLUDES, $excludes)).'}');
};
