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
use Symfony\Component\Routing\RouterInterface;
use MauticPlugin\MauticLdapAuthBundle\Integration\LdapFormAuthIntegration;

/**
 * Class UserSubscriber.
 */
class UserSubscriber implements EventSubscriberInterface
{

    private $supportedServices = [
        'LdapFormAuth',
        'LdapAuth',

    ];

    public function __construct(private readonly CoreParametersHelper $parametersHelper, private readonly RouterInterface $router)
    {
    }

    /**
     * @return array
     */
    public static function getSubscribedEvents()
    {
        return [
//            UserEvents::USER_FORM_AUTHENTICATION => ['onUserFormAuthentication', 0],
            UserEvents::USER_FORM_AUTHENTICATION => ['onUserAuthentication2', 10],
            UserEvents::USER_FORM_POST_LOCAL_PASSWORD_AUTHENTICATION => ['onUserFormPostLocalAuthentication', 10],
//            UserEvents::USER_PRE_AUTHENTICATION  => ['onUserAuthentication', 0],
        ];
    }

    public function onUserAuthentication2(AuthenticationEvent $event){
        $username = $event->getUsername();
        $password = $event->getToken()->getCredentials();

        $username = $event->getRequest()->get('_username');
        $password = $event->getRequest()->get('_password');
        $integration = null;
        $result      = false;
        if ($authService = $event->getAuthenticatingService()) {
            if (in_array($authService, $this->supportedServices)
                && $integration = $event->getIntegration($authService)) {
                $result = $this->authenticateService($integration, $username, $password);
            }
        } else {
            foreach ($this->supportedServices as $supportedService) {
                if ($integration = $event->getIntegration($supportedService)) {
                    $authService = $supportedService;
                    $result      = $this->authenticateService($integration, $username, $password);
                    break;
                }
            }
        }

        if ($integration && $result instanceof User) {
            $event->setIsAuthenticated($authService, $result, $integration->shouldAutoCreateNewUser());
        } elseif ($result instanceof Response) {
            $event->setResponse($result);
        } // else do nothing
    }

    public function onUserAuthentication(AuthenticationEvent $event)
    {

        $username = $event->getRequest()->get('_username');
        $password = $event->getRequest()->get('_password');
        $authenticatingService = $event->getAuthenticatingService();

        if(!in_array(LdapFormAuthIntegration::NAME, $this->supportedServices)) {
            return;
        }

        $integration = $event->getIntegration($authenticatingService);

        if (!$integration instanceof LdapFormAuthIntegration) {
            throw new \RuntimeException('The integration is not found.');
        }

        $integration->setCoreParametersHelper($this->parametersHelper);
        $integration->setUserProvider($event->getUserProvider());

        $result = $this->authenticateService($integration, $username, $password);

        if ($integration && $result instanceof User) {
            $event->setIsAuthenticated(LdapFormAuthIntegration::NAME, $result, $integration->shouldAutoCreateNewUser());
        } elseif ($result instanceof Response) {
            $event->setResponse($result);
        }

    }

    /**
     * Authenticate via the form using users defined in LDAP server(s).
     *
     * @return bool|void
     */
    public function onUserFormAuthentication(AuthenticationEvent $event)
    {
        $username = $event->getRequest()->get('_username');
        $password = $event->getRequest()->get('_password');


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
//        dd($integration, $result);
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
    private function authenticateService($integration, $username, $password)
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

//dd($integration->ssoAuthCallback($settings, $parameters));
        return false;
    }

    public function onUserFormPostLocalAuthentication(AuthenticationEvent $event): void
    {
        $event->stopPropagation();
    }

//    private function authenticateService2(LeuchtfeuerAuth0Integration $integration, bool $loginCheck)
//    {
//        if ($loginCheck) {
//            /** @var false|User $authenticatedUser */
//            $authenticatedUser = $integration->ssoAuthCallback();
//            if ($authenticatedUser instanceof User) {
//                return $authenticatedUser;
//            }
//        } else {
//            $loginUrl = $integration->getAuthLoginUrl();
//            $response = new RedirectResponse($loginUrl);
//
//            return $response;
//        }
//
//        return false;
//    }
    public function shouldAutoCreateNewUser(): bool
    {
        return true;
    }
}
