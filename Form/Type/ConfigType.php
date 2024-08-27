<?php

namespace MauticPlugin\MauticLdapAuthBundle\Form\Type;

use Mautic\CoreBundle\Form\Type\YesNoButtonGroupType;
use Mautic\CoreBundle\Helper\CoreParametersHelper;
use Symfony\Component\Form\AbstractType;
use Symfony\Component\Form\Extension\Core\Type\NumberType;
use Symfony\Component\Form\Extension\Core\Type\TextType;
use Symfony\Component\Form\Extension\Core\Type\UrlType;
use Symfony\Component\Form\FormBuilderInterface;
use Symfony\Contracts\Translation\TranslatorInterface;

/**
 * Class ConfigType.
 */
class ConfigType extends AbstractType
{
    /**
     * @var CoreParametersHelper
     */
    protected $parameters;

    /**
     * @var TranslatorInterface
     */
    protected $translator;

    /**
     * ConfigType constructor.
     */
    public function __construct(CoreParametersHelper $parametersHelper, TranslatorInterface $translator)
    {
        $this->parameters = $parametersHelper;
        $this->translator = $translator;
    }

    public function buildForm(FormBuilderInterface $builder, array $options)
    {
        $builder->add(
            'ldap_auth_host',
            UrlType::class,
            [
                'label'      => 'mautic.integration.sso.ldapauth.config.form.host',
                'label_attr' => ['class' => 'control-label'],
                'attr'       => [
                    'class'   => 'form-control',
                    'tooltip' => 'mautic.integration.sso.ldapauth.config.form.host.tooltip',
                ],
                'default_protocol' => 'ldap',
            ]
        );

        $builder->add(
            'ldap_auth_port',
            NumberType::class,
            [
                'label'      => 'mautic.integration.sso.ldapauth.config.form.port',
                'label_attr' => ['class' => 'control-label'],
                'attr'       => [
                    'class'   => 'form-control',
                    'tooltip' => 'mautic.integration.sso.ldapauth.config.form.port.tooltip',
                ],
                'empty_data' => 389,
            ]
        );

        $builder->add(
            'ldap_auth_ssl',
            YesNoButtonGroupType::class,
            [
                'label'      => 'mautic.integration.sso.ldapauth.config.form.ssl',
                'label_attr' => ['class' => 'control-label'],
                'attr'       => [
                    'class'   => 'form-control',
                    'tooltip' => 'mautic.integration.sso.ldapauth.config.form.ssl.tooltip',
                ],
                'data' => isset($options['data']['ldap_auth_ssl']) ?
                    (bool) $options['data']['ldap_auth_ssl']
                    : (
                        isset($options['data']['ldap_auth_host']) ?
                            'ldaps://' === substr($options['data']['ldap_auth_host'], 0, 8)
                            : false
                    ),
                'empty_data' => false,
            ]
        );
        $builder->add(
            'ldap_auth_starttls',
            YesNoButtonGroupType::class,
            [
                'label'      => 'mautic.integration.sso.ldapauth.config.form.starttls',
                'label_attr' => ['class' => 'control-label'],
                'attr'       => [
                    'class'   => 'form-control',
                    'tooltip' => 'mautic.integration.sso.ldapauth.config.form.starttls.tooltip',
                ],
                'data' => isset($options['data']['ldap_auth_starttls']) ?
                    (bool) $options['data']['ldap_auth_starttls']
                    : false,
                'empty_data' => false,
            ]
        );

        $builder->add(
            'ldap_auth_version',
            NumberType::class,
            [
                'label'      => 'mautic.integration.sso.ldapauth.config.form.version',
                'label_attr' => ['class' => 'control-label'],
                'attr'       => [
                    'class'   => 'form-control',
                    'tooltip' => 'mautic.integration.sso.ldapauth.config.form.version.tooltip',
                ],
                'empty_data' => 3,
                'required'   => false,
            ]
        );

        $builder->add(
            'ldap_auth_base_dn',
            TextType::class,
            [
                'label'      => 'mautic.integration.sso.ldapauth.config.form.base_dn',
                'label_attr' => ['class' => 'control-label'],
                'attr'       => [
                    'class'   => 'form-control',
                    'tooltip' => 'mautic.integration.sso.ldapauth.config.form.base_dn.tooltip',
                ],
                'empty_data' => null,
            ]
        );
        $builder->add(
            'ldap_auth_user_query',
            TextType::class,
            [
                'label'      => 'mautic.integration.sso.ldapauth.config.form.user_query',
                'label_attr' => ['class' => 'control-label'],
                'attr'       => [
                    'class'   => 'form-control',
                    'tooltip' => 'mautic.integration.sso.ldapauth.config.form.user_query.tooltip',
                ],
                'empty_data' => '(objectclass=inetOrgPerson)',
            ]
        );

        $builder->add(
            'ldap_auth_isactivedirectory',
            YesNoButtonGroupType::class,
            [
                'label'      => 'mautic.integration.sso.ldapauth.config.form.isactivedirectory',
                'label_attr' => ['class' => 'control-label'],
                'attr'       => [
                    'class'   => 'form-control',
                    'tooltip' => 'mautic.integration.sso.ldapauth.config.form.isactivedirectory.tooltip',
                ],
                'data' => isset($options['data']['ldap_auth_isactivedirectory']) ?
                    (bool) $options['data']['ldap_auth_isactivedirectory']
                    : false,
                'empty_data' => false,
                'required'   => false,
            ]
        );
        $builder->add(
            'ldap_auth_activedirectory_domain',
            TextType::class,
            [
                'label'      => 'mautic.integration.sso.ldapauth.config.form.activedirectory_domain',
                'label_attr' => ['class' => 'control-label'],
                'attr'       => [
                    'class'   => 'form-control',
                    'tooltip' => 'mautic.integration.sso.ldapauth.config.form.activedirectory_domain.tooltip',
                ],
                'empty_data' => null,
                'required'   => false,
            ]
        );

        $builder->add(
            'ldap_auth_username_attribute',
            TextType::class,
            [
                'label'      => 'mautic.integration.sso.ldapauth.config.form.username_attribute',
                'label_attr' => ['class' => 'control-label'],
                'attr'       => [
                    'class'   => 'form-control',
                    'tooltip' => 'mautic.integration.sso.ldapauth.config.form.username_attribute.tooltip',
                ],
                'empty_data' => 'uid',
            ]
        );

        $builder->add(
            'ldap_auth_email_attribute',
            TextType::class,
            [
                'label'      => 'mautic.integration.sso.ldapauth.config.form.email_attribute',
                'label_attr' => ['class' => 'control-label'],
                'attr'       => [
                    'class'   => 'form-control',
                    'tooltip' => 'mautic.integration.sso.ldapauth.config.form.email_attribute.tooltip',
                ],
                'empty_data' => 'mail',
            ]
        );

        $builder->add(
            'ldap_auth_firstname_attribute',
            TextType::class,
            [
                'label'      => 'mautic.integration.sso.ldapauth.config.form.firstname_attribute',
                'label_attr' => ['class' => 'control-label'],
                'attr'       => [
                    'class'   => 'form-control',
                    'tooltip' => 'mautic.integration.sso.ldapauth.config.form.firstname_attribute.tooltip',
                ],
                'empty_data' => 'givenname',
            ]
        );

        $builder->add(
            'ldap_auth_lastname_attribute',
            TextType::class,
            [
                'label'      => 'mautic.integration.sso.ldapauth.config.form.lastname_attribute',
                'label_attr' => ['class' => 'control-label'],
                'attr'       => [
                    'class'   => 'form-control',
                    'tooltip' => 'mautic.integration.sso.ldapauth.config.form.lastname_attribute.tooltip',
                ],
                'empty_data' => 'sn',
            ]
        );

        $builder->add(
            'ldap_auth_fullname_attribute',
            TextType::class,
            [
                'label'      => 'mautic.integration.sso.ldapauth.config.form.fullname_attribute',
                'label_attr' => ['class' => 'control-label'],
                'attr'       => [
                    'class'   => 'form-control',
                    'tooltip' => 'mautic.integration.sso.ldapauth.config.form.fullname_attribute.tooltip',
                ],
                'empty_data' => 'displayname',
                'required'   => false,
            ]
        );
    }

    /**
     * {@inheritdoc}
     */
    public function getName()
    {
        return 'ldapconfig';
    }
}
