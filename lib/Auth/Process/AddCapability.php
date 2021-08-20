<?php

namespace SimpleSAML\Module\entitlement\Auth\Process;

use SimpleSAML\Auth\ProcessingFilter;
use SimpleSAML\Error\Exception;
use SimpleSAML\Logger;
use SimpleSAML\Metadata\MetaDataStorageHandler;

/**
 * Attribute filter for evaluating the resources capabilities of the
 * authenticating user. A capability defines the resource or child-resource the
 * user is allowed to access, optionally specifying certain actions the user is
 * entitled to perform. Capabilities can be used to convey – in a compact form –
 * authorisation information. Capability values are formatted as URNs following
 * the syntax specified in https://aarc-community.org/guidelines/aarc-g027
 *
 * Example config
 * XX => [
 *     'class' => 'entitlement:AddCapability',
 *     'attributeName' => "eduPersonEntitlement",
 *     'capability' => [
 *         'urn:mace:example.org:group:vo.example.org:role=member#foo.example.org',
 *     ],
 *     'idpWhitelist' => [ // or idpBlacklist
 *         'https://idp.example1.org/entityId',
 *         'https://idp.example2.org/entityId',
 *     ],
 *     'entityAttributeWhitelist' => [
 *         'http://macedir.org/entity-category-support' => [
 *             'http://refeds.org/category/research-and-scholarship',
 *         ],
 *         'urn:oasis:names:tc:SAML:attribute:assurance-certification' => [
 *             'https://refeds.org/sirtfi',
 *         ],
 *     ],
 *     'entitlementWhitelist' => [
 *         'urn:mace:idp.example.org:group:another.vo.example.org:role=member#bar.example.org',
 *     ],
 * ],
 */
class AddCapability extends ProcessingFilter
{

    /**
     * The attribute that will hold the capability value(s).
     * @var string
     */
    private $attributeName = 'eduPersonEntitlement';


    /**
     * The assigned capability value(s).
     * @var string
     */
    private $capability = [];


    /**
     * List of IdP entity IDs excluded from this capability.
     */
    private $idpBlacklist = [];


    /**
     * List of IdP entity IDs qualifying for this capability.
     */
    private $idpWhitelist = [];


    /**
     * Combination of entity attributes qualifying for this capability.
     */
    private $entityAttributeWhitelist = [];


    /**
     * List of user entitlements qualifying for this capability.
     */
    private $entitlementWhitelist = [];


    /**
     * Initialize this filter, parse configuration
     *
     * @param array $config Configuration information about this filter.
     * @param mixed $reserved For future use.
     *
     * @throws SimpleSAML\Error\Exception if the mandatory 'accepted' configuration option is missing.
     */
    public function __construct($config, $reserved)
    {
        parent::__construct($config, $reserved);
        assert('is_array($config)');

        if (array_key_exists('attributeName', $config)) {
            if (!is_string($config['attributeName'])) {
                Logger::error("[AddCapability] Configuration error: 'attributeName' not a string literal");
                throw new Exception("AddCapability configuration error: 'attributeName' not a string literal");
            }
            $this->attributeName = $config['attributeName'];
        }

        if (array_key_exists('capability', $config)) {
            if (!is_array($config['capability'])) {
                Logger::error("[AddCapability] Configuration error: 'capability' not a string literal");
                throw new Exception("AddCapability configuration error: 'capability' not a string literal");
            }
            $this->capability = $config['capability'];
        }

        if (array_key_exists('idpBlacklist', $config)) {
            if (!is_array($config['idpBlacklist'])) {
                Logger::error("[AddCapability] Configuration error: 'idpBlacklist' not a string literal");
                throw new Exception("AddCapability configuration error: 'idpBlacklist' not a string literal");
            }
            $this->idpBlacklist = $config['idpBlacklist'];
        }

        if (array_key_exists('idpWhitelist', $config)) {
            if (!is_array($config['idpWhitelist'])) {
                Logger::error("[AddCapability] Configuration error: 'idpWhitelist' not a string literal");
                throw new Exception("AddCapability configuration error: 'idpWhitelist' not a string literal");
            }
            $this->idpWhitelist = $config['idpWhitelist'];
        }

        if (array_key_exists('entityAttributeWhitelist', $config)) {
            if (!is_array($config['entityAttributeWhitelist'])) {
                Logger::error(
                    "[AddCapability] Configuration error: 'entityAttributeWhitelist' not a string literal"
                );
                throw new Exception(
                    "AddCapability configuration error: 'entityAttributeWhitelist' not a string literal"
                );
            }
            $this->entityAttributeWhitelist = $config['entityAttributeWhitelist'];
        }

        if (array_key_exists('entitlementWhitelist', $config)) {
            if (!is_array($config['entitlementWhitelist'])) {
                Logger::error(
                    "[AddCapability] Configuration error: 'entitlementWhitelist' not a string literal"
                );
                throw new Exception("AddCapability configuration error: 'entitlementWhitelist' not a string literal");
            }
            $this->entitlementWhitelist = $config['entitlementWhitelist'];
        }
    }


    /**
     *
     * @param array &$state The current SP state
     */
    public function process(&$state)
    {
        assert('is_array($state)');

        if (!$this->isQualified($state)) {
            return;
        }
        if (empty($state['Attributes'][$this->attributeName])) {
            $state['Attributes'][$this->attributeName] = [];
        }
        $state['Attributes'][$this->attributeName] = array_merge(
            $state['Attributes'][$this->attributeName],
            $this->capability
        );
        Logger::debug("[AddCapability] Adding capability " . var_export($this->capability, true));
    }


    private function isQualified($state)
    {
        assert('array_key_exists("entityid", $state["Source"])');

        // If the entitlement module is active on a bridge $state['saml:sp:IdP']
        // will contain an entry id for the remote IdP.
        if (!empty($state['saml:sp:IdP'])) {
            $idpEntityId = $state['saml:sp:IdP'];
            $idpMetadata = MetaDataStorageHandler::getMetadataHandler()->getMetaData($idpEntityId, 'saml20-idp-remote');
        } else {
            $idpEntityId = $state['Source']['entityid'];
            $idpMetadata = $state['Source'];
        }
        Logger::debug("[AddCapability] IdP="
            . var_export($idpEntityId, true));
        if (!empty($this->idpBlacklist) && in_array($idpEntityId, $this->idpBlacklist)) {
            return false;
        }
        if (!empty($this->idpWhitelist) && in_array($idpEntityId, $this->idpWhitelist)) {
            return true;
        }
        if (
            !empty($idpMetadata['EntityAttributes'])
            && empty($this->getEntityAttributesDiff($this->entityAttributeWhitelist, $idpMetadata['EntityAttributes']))
        ) {
            return true;
        }
        if (
            !empty($state['Attributes'][$this->attributeName])
            && !empty(array_intersect($state['Attributes'][$this->attributeName], $this->entitlementWhitelist))
        ) {
            return true;
        }
        return false;
    }


    private function getEntityAttributesDiff($array1, $array2)
    {
        $diff = [];
        foreach ($array1 as $key => $value) {
            if (empty($array2[$key]) || !is_array($array2[$key])) {
                $diff[$key] = $value;
            } else {
                $newDiff = array_diff($value, $array2[$key]);
                if (!empty($newDiff)) {
                    $diff[$key] = $newDiff;
                }
            }
        }
        return $diff;
    }
}
