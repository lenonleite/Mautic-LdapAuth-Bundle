<?php

namespace MauticPlugin\MauticLdapAuthBundle\EventListener;

use Mautic\CoreBundle\Helper\CoreParametersHelper;
use Mautic\PluginBundle\Integration\AbstractSsoFormIntegration;
use Mautic\UserBundle\Entity\User;
use Mautic\UserBundle\Event\AuthenticationEvent;
use Mautic\UserBundle\UserEvents;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Response;

/**
 * Class UserSubscriber.
 */
class UserSubscriber implements EventSubscriberInterface
{
    /**
     * @var CoreParametersHelper
     */
    private $parametersHelper;

    private $supportedServices = [
        'LdapAuth',
    ];

    public function __construct(CoreParametersHelper $parametersHelper)
    {
        $this->parametersHelper = $parametersHelper;
    }

    /**
     * @return array
     */
    public static function getSubscribedEvents()
    {
        return [
            UserEvents::USER_FORM_AUTHENTICATION => ['onUserFormAuthentication', 0],
        ];
    }

    /**
     * Authenticate via the form using users defined in LDAP server(s).
     *
     * @return bool|void
     */
    public function onUserFormAuthentication(AuthenticationEvent $event)
    {
        $username = $event->getUsername();
        $password = $event->getToken()->getCredentials();

        $integration = null;
        $result      = false;
        if ($authenticatingService = $event->getAuthenticatingService()) {
            if (in_array($authenticatingService, $this->supportedServices)
                && $integration = $event->getIntegration($authenticatingService)) {
                $result = $this->authenticateService($integration, $username, $password);
            }
        } else {
            foreach ($this->supportedServices as $supportedService) {
                if ($integration = $event->getIntegration($supportedService)) {
                    $authenticatingService = $supportedService;
                    $result                = $this->authenticateService($integration, $username, $password);
                    break;
                }
            }
        }

        if ($integration && $result instanceof User) {
            $event->setIsAuthenticated($authenticatingService, $result, $integration->shouldAutoCreateNewUser());
        } elseif ($result instanceof Response) {
            $event->setResponse($result);
        } // else do nothing
    }

    /**
     * @param string $username
     * @param string $password
     *
     * @return bool|RedirectResponse
     */
    private function authenticateService(AbstractSsoFormIntegration $integration, $username, $password)
    {
        $settings = [
            'hostname'      => $this->parametersHelper->get('ldap_auth_host'),
            'port'          => $this->parametersHelper->get('ldap_auth_port', 389),
            'ssl'           => $this->parametersHelper->get('ldap_auth_ssl', false),
            'starttls'      => $this->parametersHelper->get('ldap_auth_starttls', true),
            'version'       => $this->parametersHelper->get('ldap_auth_version', 3),
            // TODO Coming feature: Bind DN
            // 'bind_dn'       => $this->parametersHelper->getParameter('ldap_auth_bind_dn'),
            // 'bind_passwd'   => $this->parametersHelper->getParameter('ldap_auth_bind_passwd'),
            'base_dn'       => $this->parametersHelper->get('ldap_auth_base_dn'),
            'user_query'    => $this->parametersHelper->get('ldap_auth_user_query', ''),
            'is_ad'         => $this->parametersHelper->get('ldap_auth_isactivedirectory', false),
            'ad_domain'     => $this->parametersHelper->get('ldap_auth_activedirectory_domain', null),
            'user_key'      => $this->parametersHelper->get('ldap_auth_username_attribute', 'uid'),
            'user_email'    => $this->parametersHelper->get('ldap_auth_email_attribute', 'mail'),
            'user_firstname'=> $this->parametersHelper->get('ldap_auth_firstname_attribute', 'givenName'),
            'user_lastname' => $this->parametersHelper->get('ldap_auth_lastname_attribute', 'sn'),
            'user_fullname' => $this->parametersHelper->get('ldap_auth_fullname_attribute', 'displayName'),
        ];

        $parameters = [
            'login'     => $username,
            'password'  => $password,
        ];

        if ($authenticatedUser = $integration->ssoAuthCallback($settings, $parameters)) {
            return $authenticatedUser;
        }

        return false;
    }
}
