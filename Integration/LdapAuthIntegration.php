<?php

namespace MauticPlugin\MauticLdapAuthBundle\Integration;

use Doctrine\ORM\EntityManager;
use Mautic\CoreBundle\Form\Type\YesNoButtonGroupType;
use Mautic\CoreBundle\Helper\CacheStorageHelper;
use Mautic\CoreBundle\Helper\CoreParametersHelper;
use Mautic\CoreBundle\Helper\EncryptionHelper;
use Mautic\CoreBundle\Helper\PathsHelper;
use Mautic\CoreBundle\Model\NotificationModel;
use Mautic\LeadBundle\Model\CompanyModel;
use Mautic\LeadBundle\Model\DoNotContact as DoNotContactModel;
use Mautic\LeadBundle\Model\FieldModel;
use Mautic\LeadBundle\Model\LeadModel;
use Mautic\PluginBundle\Integration\AbstractSsoFormIntegration;
use Mautic\PluginBundle\Integration\AbstractSsoServiceIntegration;
use Mautic\PluginBundle\Model\IntegrationEntityModel;
use Mautic\UserBundle\Entity\User;
use Mautic\UserBundle\Form\Type\RoleListType;
use Mautic\UserBundle\Model\UserModel;
use Mautic\UserBundle\Security\Provider\UserProvider;
use MauticPlugin\MauticLdapAuthBundle\Integration\Form;
use Psr\Log\LoggerInterface;
use Symfony\Component\EventDispatcher\EventDispatcherInterface;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\HttpFoundation\Session\SessionInterface;
use Symfony\Component\Ldap\Ldap;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasher;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;
use Symfony\Component\Routing\RouterInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Contracts\Translation\TranslatorInterface;

/**
 * Class LdapAuthIntegration.
 */
class LdapAuthIntegration extends AbstractSsoFormIntegration
//class LdapAuthIntegrationBackup extends AbstractSsoServiceIntegration
{
    public const NAME = 'LdapAuth';

//    protected CoreParametersHelper $coreParametersHelper;

//    protected UserProvider $userProvider;

//    protected UserPasswordHasher $hasher;
//
//    protected UserModel $userModel;

    public function __construct(
        protected EventDispatcherInterface $dispatcher,
        CacheStorageHelper $cacheStorageHelper,
        protected EntityManager $em,
        SessionInterface $session,
        RequestStack $requestStack,
        protected RouterInterface $router,
        protected TranslatorInterface $translator,
        protected LoggerInterface $logger,
        protected EncryptionHelper $encryptionHelper,
        protected LeadModel $leadModel,
        protected CompanyModel $companyModel,
        protected PathsHelper $pathsHelper,
        protected NotificationModel $notificationModel,
        protected FieldModel $fieldModel,
        protected IntegrationEntityModel $integrationEntityModel,
        protected DoNotContactModel $doNotContact,
        protected UserPasswordHasherInterface $hasher,
        protected UserModel $userModel,
        protected CoreParametersHelper $coreParametersHelper,
        protected UserProvider $userProvider

    ) {
        parent::__construct(
            $this->dispatcher,
            $cacheStorageHelper,
            $this->em,
            $session,
            $requestStack,
            $this->router,
            $this->translator,
            $this->logger,
            $this->encryptionHelper,
            $this->leadModel,
            $this->companyModel,
            $this->pathsHelper,
            $this->notificationModel,
            $this->fieldModel,
            $this->integrationEntityModel,
            $this->doNotContact);


    }
//    public function __construct(CoreParametersHelper $coreParametersHelper, UserProvider $userProvider, UserPasswordHasher $hasher, UserModel $userModel)
//    {
//        $this->coreParametersHelper = $coreParametersHelper;
//        $this->userProvider = $userProvider;
//        $this->hasher = $hasher;
//        $this->userModel = $userModel;
//    }

    /**
     * @return string
     */
    public function getName()
    {
        return self::NAME;
    }

    public function getDisplayName(): string
    {
        return 'LDAP Authentication';
    }

    public function getAuthenticationType(): string
    {
        return 'none';
    }

    /**
     * {@inheritdoc}
     */
    public function getRequiredKeyFields(): array
    {
        return [
        ];
    }

    /**
     * {@inheritdoc}
     */
    public function getSecretKeys(): array
    {
        return [
        ];
    }

    /**
     * {@inheritdoc}
     */
    public function getAuthTokenKey(): string
    {
        return '';
    }

    /**
     * Set in the UserSubscriber.
     */
    public function setCoreParametersHelper(CoreParametersHelper $coreParametersHelper): void
    {
        $this->coreParametersHelper = $coreParametersHelper;
    }

    /**
     * Set in the UserSubscriber.
     */
    public function setUserProvider(UserProvider $userProvider): void
    {
        $this->userProvider = $userProvider;
    }

    /**
     * {@inheritdoc}
     *
     * @param array $settings
     * @param array $parameters
     *
     * @return bool|array false if no error; otherwise the error string
     *
     * @throws AuthenticationException
     */
    public function authCallback($settings = [], $parameters = []): bool|array
    {
//        dd($settings,$parameters);
        $hostname    = $settings['hostname'];
        $port        = (int) $settings['port'];
        $ssl         = (bool) $settings['ssl'];
        $startTls    = (bool) $settings['starttls'];
        $ldapVersion = !empty($settings['version']) ? (int) $settings['version'] : 3;
        $baseHost    = 'ldap://';

        if ('ldap://' === substr($hostname, 0, 7)) {
            $hostname = str_replace('ldap://', '', $hostname);
        } elseif ('ldaps://' === substr($hostname, 0, 8)) {
            $ssl      = true;
            $startTls = false;
            $baseHost = 'ldaps://';
            $hostname = str_replace('ldaps://', '', $hostname);
        }

        if (empty($port)) {
            if ($ssl) {
                $port = 636;
            } else {
                $port = 389;
            }
        }

        if (!empty($hostname) && !empty($parameters['login'])) {
            $connectionString = "$baseHost.$hostname:$port";
            if(filter_var($hostname, FILTER_VALIDATE_IP) !== false) {
                $connectionString = "$baseHost$hostname:$port";
            }

            $ldap = Ldap::create(
                'ext_ldap',
                [
                    'connection_string' => $connectionString,
                ]
            );

            $response = $this->ldapUserLookup($ldap, $settings, $parameters);
            if(!$this->checkLdapUserLookup($response)) {
                return false;
            }
            return $this->extractAuthKeys($response);
        }

        return false;
    }

    /**
     * Check if the LDAP user lookup was successful.
     *
     * @param array $response
     *
     * @return bool
     */
    private function checkLdapUserLookup($response): bool
    {
        if (is_array($response) && !empty($response) && isset($response['errors'])) {
            foreach ($response['errors'] as $error) {
                $this->logger->warning('LDAP Auth: '.$error);
                $this->logger->error('LDAP Auth: '.$error);
            }
            return false;
        }
        return true;
    }

    /**
     * LDAP authentication and lookup user information.
     *
     * @param Ldap  $ldap
     * @param array $settings
     * @param array $parameters
     *
     * @return array array containing the LDAP lookup results or error message(s)
     *
     * @throws AuthenticationException
     */
    private function ldapUserLookup($ldap, $settings = [], $parameters = [])
    {
        $base_dn   = $settings['base_dn'];
        $userKey   = $settings['user_key'];
        $query     = $settings['user_query'];
        $query2     = $settings['user_query'];
        $is_ad     = $settings['is_ad'];
        $ad_domain = $settings['ad_domain'];

        $login    = $parameters['login'];
        $password = $parameters['password'];

        try {
            if ($is_ad) {
                $dn = "$login@$ad_domain";
            } else {
                $dn = "$userKey=$login,$base_dn";
            }

            $userquery = "$userKey=$login";
            $query     = "(&($userquery)$query)"; // original $query already has brackets!
//            $query     = "$userquery"; // original $query already has brackets!
            $dn2 = 'cn=admin,dc=example,dc=org';
//            dump($dn,$password,$query);
//            dump($dn,$query,$password);
            $ldap->bind($dn, $password);
//            dd($ldap);
            $base_dn2 = 'dc=example,dc=org';
//            dump($dn,$base_dn,$query);
            $response = $ldap->query($dn, $query)->execute();
//            dump($response);
//            foreach ($response as $entry) {
//                dump($entry->getDn(),$entry->getAttributes(),'entry',$entry);
//            }
            $result = [];
            $result['settings'] = $settings;
            if($response->count() >= 0) {
                foreach ($response as $key => $entry) {
                    $result[$key] = $entry->getAttributes();
                    $result[$key]['password'] = $password;
                }
            }

//            foreach ( as $iterator){
//                $result[] = $iterator->getAttributes();
//            }
//            dd($response,$response->toArray());
//            $result = $response->toArray();
//            dump($result,'result');
//            dd($response->toArray());
            // If we reach this far, we expect to have found something
            // and join the settings to the response to retrieve user fields
        } catch (\Exception $e) {
            $result = [
                'errors' => [
                    $this->getTranslator()->trans(
                        'mautic.integration.sso.ldapauth.error.authentication_issue',
                        [],
                        'flashes'
                    ),
                    $e->getMessage(),
                ],
            ];
//            dd($response);
        }

        return $result;
    }

    /**
     * {@inheritdoc}
     *
     * @return bool|array false if no error; otherwise the error string
     *
     * @throws AuthenticationException
     */
    public function extractAuthKeys($data, $tokenOverride = null)
    {
        // Prepare the keys for extraction such as renaming, setting expiry, etc

        $data = $this->prepareResponseForExtraction($data);

//        dd($data,'=====');

        // Parse the response
        if (is_array($data) && !empty($data) && isset($data['settings'])) {
            return [
                'data'     => $data[0],
                'settings' => $data['settings'],
            ];
        }
        $error = $this->getErrorsFromResponse($data);
        if (empty($error)) {
            $error = $this->getTranslator()->trans(
                'mautic.integration.error.genericerror',
                [],
                'flashes'
            );
        }

        $fallback = $this->shouldFallbackToLocalAuth();
        if (!$fallback) {
            throw new AuthenticationException($error);
        } else {
            $this->getLogger()->error($error);
        }
    }

    public function getErrorsFromResponse($data)
    {
        if (is_string($data) && str_contains($data, 'Invalid credentials') && !str_contains($data, 'search result')) {
            return $data;
        }
        return '';

    }

    /**
     * {@inheritdoc}
     *
     * @param mixed $response
     *
     * @return mixed
     *
     * @throws \Doctrine\ORM\ORMException
     */
    public function getUser($response)
    {

        if (is_array($response) && isset($response['settings']) && isset($response['data'])) {
            $settings      = $response['settings'];
            $userKey       = $settings['user_key'];
            $userEmail     = $settings['user_email'];
            $userFirstname = $settings['user_firstname'];
            $userLastname  = $settings['user_lastname'];
            $userFullname  = $settings['user_fullname'];
            $data  = $response['data'];

            $login = self::arrayGet($data, $userKey, [null])[0];
            $email = self::arrayGet($data, $userEmail, [null])[0];

            if (empty($login) || empty($email)) {
                // Login or email could not be found so bail
                return false;
            }

            $firstname = self::arrayGet($data, $userFirstname, [null])[0];
            $lastname  = self::arrayGet($data, $userLastname, [null])[0];


            if ((empty($firstname) || empty($lastname)) && isset($data[$userFullname])) {
                $names = explode(' ', $data[$userFullname][0]);
                if (count($names) > 1) {
                    $firstname = $names[0];
                    unset($names[0]);
                    $lastname = implode(' ', $names);
                } else {
                    $firstname = $lastname = $names[0];
                }
            }

//            dd($email,$data);
            $user = $this->em->getRepository(\Mautic\UserBundle\Entity\User::class)->findOneBy(['username' => $login]);
            if(!empty($user)) {
                return $user;
            }
//            dd($settings,$data,$user);
//            $mauticUser
//                ->setUsername($this->getStringValue('auth0_username', 'email'))
//                ->setEmail($this->getStringValue('auth0_email', 'email'))
//                ->setFirstName($this->getStringValue('auth0_firstName', 'given_name'))
//                ->setLastName($this->getStringValue('auth0_lastName', 'family_name'))
//                ->setTimezone($this->getStringValue('auth0_timezone'))
//                ->setLocale($this->getStringValue('auth0_locale'))
//                ->setSignature($this->getStringValue('auth0_signature'))
//                ->setPosition($this->getStringValue('auth0_position'));

            $user = new User();
            $user->setUsername($login)
                ->setEmail($email)
                ->setFirstName($firstname)
                ->setLastName($lastname)
                ->setRole(
                    $this->getUserRole()
                )->setIsPublished(true)
                ->setActivePermissions([])
            ->setTimezone('UTC')
            ->setLocale('en')
            ->setSignature('')
            ->setPosition('');
            $password = $this->userModel->checkNewPassword($user,$this->hasher, $response['data']['password']);
            $user->setPassword($password);
//            dd($user);
            return $user;
        }

        return false;
    }

    /**
     * Get a value from an array or return default value if not set.
     *
     * @param array  $array   source array
     * @param string $key     key to get from array
     * @param mixed  $default default value if key not set in array
     *
     * @return mixed a value from array or default value
     */
    private function arrayGet($array, $key, $default = null)
    {
        return isset($array[$key]) ? $array[$key] : $default;
    }

    /**
     * Returns if failed LDAP authentication should fallback to local authentication.
     *
     * @return bool
     */
    public function shouldFallbackToLocalAuth()
    {
        $featureSettings = $this->settings->getFeatureSettings();

        return (isset($featureSettings['auth_fallback'])) ? $featureSettings['auth_fallback'] : true;
    }

    /**
     * {@inheritdoc}
     *
     * @param Form|\Symfony\Component\Form\FormBuilder $builder
     * @param array                                    $data
     * @param string                                   $formArea
     */
    public function appendToForm(&$builder, $data, $formArea): void
    {
        if ('features' == $formArea) {
            $builder->add(
                'auth_fallback',
                YesNoButtonGroupType::class,
                [
                    'label' => 'mautic.integration.sso.ldapauth.auth_fallback',
                    'data'  => (isset($data['auth_fallback'])) ? (bool) $data['auth_fallback'] : true,
                    'attr'  => [
                        'tooltip' => 'mautic.integration.sso.ldapauth.auth_fallback.tooltip',
                    ],
                ]
            );

            $builder->add(
                'auto_create_user',
                YesNoButtonGroupType::class,
                [
                    'label' => 'mautic.integration.sso.auto_create_user',
                    'data'  => (isset($data['auto_create_user'])) ? (bool) $data['auto_create_user'] : false,
                    'attr'  => [
                        'tooltip' => 'mautic.integration.sso.auto_create_user.tooltip',
                    ],
                ]
            );

            $builder->add(
                'new_user_role',
                RoleListType::class,
                [
                    'label'      => 'mautic.integration.sso.new_user_role',
                    'label_attr' => ['class' => 'control-label'],
                    'attr'       => [
                        'class'   => 'form-control',
                        'tooltip' => 'mautic.integration.sso.new_user_role.tooltip',
                    ],
                ]
            );
        }
    }

    /**
     * Set the callback URL to sso_login.
     */
    public function getAuthCallbackUrl(): string
    {
        return sprintf(
            '%s://%s%s',
            $this->router->getContext()->getScheme(),
            $this->router->getContext()->getHost(),
            $this->router->generate('mautic_sso_login_check',
                ['integration' => $this->getName()],
                UrlGeneratorInterface::ABSOLUTE_PATH
            )
        );
    }
}
