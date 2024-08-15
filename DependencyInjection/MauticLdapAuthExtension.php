<?php

declare(strict_types=1);

namespace MauticPlugin\MauticLdapAuthBundle\DependencyInjection;

use Symfony\Component\Config\FileLocator;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Extension\Extension;
use Symfony\Component\DependencyInjection\Extension\PrependExtensionInterface;
use Symfony\Component\DependencyInjection\Loader\PhpFileLoader;

class MauticLdapAuthExtension extends Extension implements PrependExtensionInterface
{
    /**
     * @param mixed[] $configs
     */
    public function load(array $configs, ContainerBuilder $container): void
    {
        $loader = new PhpFileLoader($container, new FileLocator(__DIR__.'/../Config'));
        $loader->load('services.php');
    }

    public function prepend(ContainerBuilder $container): void
    {
        $container->loadFromExtension('twig', [
            'paths' => [
                '%mautic.application_dir%/plugins/MauticLdapAuthBundle/Resources/User/views' => 'MauticUser', // You use the namespace you found earlier here. Discard the `@` symbol.
            ],
        ]);
    }
}
