<?php

namespace MauticPlugin\MauticLdapAuthBundle\Tests\Functional;

use Mautic\CoreBundle\Test\MauticMysqlTestCase;
use Mautic\PluginBundle\Entity\Integration;
use Mautic\PluginBundle\Entity\Plugin;
use Symfony\Component\HttpFoundation\Request;

class ConfigSubscriberTest extends MauticMysqlTestCase
{
    //    public function setUp(): void
    //    {
    //
    //    }

    public function testOnConfigGenerate(): void
    {
        $this->client->request('GET', '/s/config/edit');
        $this->assertEquals(200, $this->client->getResponse()->getStatusCode());
        $this->assertStringContainsString('LDAP Settings', $this->client->getResponse()->getContent());
        $this->assertStringContainsString('LDAP Server host', $this->client->getResponse()->getContent());
    }

    public function testOnConfigSave(): void
    {
        //        $this->client->request('POST', '/s/config/edit', ['config[ldapconfig][ldap_auth_host]' => 'ldaps://ldap.example.com']);
        $ldapExample                                       = 'ldaps://ldap.example.com';
        $crawler                                           = $this->client->request('GET', '/s/config/edit');
        $form                                              = $crawler->filter('form[name=config]')->form();
        $formValues                                        = $form->getValues();
        $formValues['config[ldapconfig][ldap_auth_host]']  = $ldapExample;
        $formValues['config[ldapconfig][ldap_auth_port]']  = '444';
        $formValues['config[coreconfig][site_url]']        = 'https://mautic-community.local';
        $form->setValues($formValues);
        $crawler = $this->client->submit($form);
        $this->assertEquals(200, $this->client->getResponse()->getStatusCode());
        $this->assertStringContainsString($ldapExample, $this->client->getResponse()->getContent());
        $this->assertStringContainsString('444', $this->client->getResponse()->getContent());
    }

    public function testFallbackLocalAuth(): void
    {
        $this->activePlugin();
        $crawler                             = $this->client->request('GET', '/s/plugins/config/LdapAuth');
        $form                                = $crawler->selectButton('Save')->form();
        $formValues                          = $form->getValues();
        $this->assertEquals('1', $formValues['integration_details[featureSettings][auth_fallback]']);
        $formValues['integration_details[featureSettings][auth_fallback]']  = '0';
        $form->setValues($formValues);
        $crawler     = $this->client->submit($form);
        $integration = $this->em->getRepository(Integration::class)->findOneBy(['name' => 'LdapAuth']);
        $this->assertEquals('0', $integration->getFeatureSettings()['auth_fallback']);
        $crawler           = $this->client->request(Request::METHOD_GET, '/s/logout');
        $form              = $crawler->selectButton('login')->form();
        $form['_username'] = 'admin';
        $form['_password'] = 'password';
        $crawler           = $this->client->submit($form);
        $this->assertEquals(200, $this->client->getResponse()->getStatusCode());
        $this->assertStringContainsString('LDAP authentication problem;', $this->client->getResponse()->getContent());
    }

    private function activePlugin($isPublished = true)
    {
        $this->client->request('GET', '/s/plugins/reload');
        $integration = $this->em->getRepository(Integration::class)->findOneBy(['name' => 'LdapAuth']);
        if (empty($integration)) {
            $plugin      = $this->em->getRepository(Plugin::class)->findOneBy(['bundle' => 'MauticLdapAuthBundle']);
            $integration = new Integration();
            $integration->setName('LdapAuth');
            $integration->setPlugin($plugin);
        }
        $integration->setIsPublished($isPublished);
        $this->em->persist($integration);
        $this->em->flush();
        $_SERVER['REQUEST_METHOD'] = 'POST';
        $this->client->request('GET', '/s/plugins/reload');
        $this->useCleanupRollback = false;
        $this->setUpSymfony($this->configParams);
    }
}
