<?php

/**
 * Attribute filter to evaluate entitlement for access to Services.
 *
 */
class sspmod_entitlement_Auth_Process_ΕvaluateΕntitlement extends SimpleSAML_Auth_ProcessingFilter
{

    /**
     * The attribute that will hold the entitlement value.
     * @var string
     */
    private $attributeName = 'eduPersonEntitlement';


    /**
     * The assigned entitlement value.
     * @var string
     */
    private $entitlement = array();


    /**
     * List of IdP entity IDs excluded from this entitlement.
     */
    private $idpBlacklist = array();


    /**
     * List of IdP entity IDs qualifying for this entitlement.
     */
    private $idpWhitelist = array();


    /**
     * Combination of entity attributes qualifying for this entitlement.
     */
    private $entityAttributeWhitelist = array();


    /**
     * List of user entitlements qualifying for this entitlement.
     */
    private $entitlementWhitelist = array();


    /**
     * Initialize this filter, parse configuration
     *
     * @param array $config Configuration information about this filter.
     * @param mixed $reserved For future use.
     *
     * @throws SimpleSAML_Error_Exception if the mandatory 'accepted' configuration option is missing.
     */
    public function __construct($config, $reserved)
    {
        parent::__construct($config, $reserved);
        assert('is_array($config)');

        if (array_key_exists('attributeName', $config)) {
            if (!is_string($config['attributeName'])) {
                SimpleSAML_Logger::error("[ΕvaluateΕntitlement] Configuration error: 'attributeName' not a string literal");
                throw new Exception("ΕvaluateΕntitlement configuration error: 'attributeName' not a string literal");
            }
            $this->attributeName = $config['attributeName'];
        }

        if (array_key_exists('entitlement', $config)) {
            if (!is_array($config['entitlement'])) {
                SimpleSAML_Logger::error("[ΕvaluateΕntitlement] Configuration error: 'entitlement' not a string literal");
                throw new Exception("ΕvaluateΕntitlement configuration error: 'entitlement' not a string literal");
            }
            $this->entitlement = $config['entitlement'];
        }

        if (array_key_exists('idpBlacklist', $config)) {
            if (!is_array($config['idpBlacklist'])) {
                SimpleSAML_Logger::error("[ΕvaluateΕntitlement] Configuration error: 'idpBlacklist' not a string literal");
                throw new Exception("ΕvaluateΕntitlement configuration error: 'idpBlacklist' not a string literal");
            }
            $this->idpBlacklist = $config['idpBlacklist'];
        }

        if (array_key_exists('idpWhitelist', $config)) {
            if (!is_array($config['idpWhitelist'])) {
                SimpleSAML_Logger::error("[ΕvaluateΕntitlement] Configuration error: 'idpWhitelist' not a string literal");
                throw new Exception("ΕvaluateΕntitlement configuration error: 'idpWhitelist' not a string literal");
            }
            $this->idpWhitelist = $config['idpWhitelist'];
        }

        if (array_key_exists('entityAttributeWhitelist', $config)) {
            if (!is_array($config['entityAttributeWhitelist'])) {
                SimpleSAML_Logger::error("[ΕvaluateΕntitlement] Configuration error: 'entityAttributeWhitelist' not a string literal");
                throw new Exception("ΕvaluateΕntitlement configuration error: 'entityAttributeWhitelist' not a string literal");
            }
            $this->entityAttributeWhitelist = $config['entityAttributeWhitelist'];
        }

        if (array_key_exists('entitlementWhitelist', $config)) {
            if (!is_array($config['entitlementWhitelist'])) {
                SimpleSAML_Logger::error("[ΕvaluateΕntitlement] Configuration error: 'entitlementWhitelist' not a string literal");
                throw new Exception("ΕvaluateΕntitlement configuration error: 'entitlementWhitelist' not a string literal");
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
            $state['Attributes'][$this->attributeName] = array();
        }
        $state['Attributes'][$this->attributeName] = array_merge($state['Attributes'][$this->attributeName], $this->entitlement);
    }


    private function isQualified($state)
    {
        assert('array_key_exists("entityid", $state["Source"])');

        // If the entitlement module is active on a bridge $state['saml:sp:IdP']
        // will contain an entry id for the remote IdP.
        if (!empty($state['saml:sp:IdP'])) {
            $idpEntityId = $state['saml:sp:IdP'];
            $idpMetadata = SimpleSAML_Metadata_MetaDataStorageHandler::getMetadataHandler()->getMetaData($idpEntityId, 'saml20-idp-remote');
        } else {
            $idpEntityId = $state['Source']['entityid'];
            $idpMetadata = $state['Source'];
        }
        SimpleSAML_Logger::debug("[entitlement:GGUS] IdP="
            . var_export($idpEntityId, true));
        if (!empty($this->idpBlacklist) && in_array($idpEntityId, $this->idpBlacklist)) {
            return false;
        }
        if (!empty($this->idpWhitelist) && in_array($idpEntityId, $this->idpWhitelist)) {
            return true;
        }
        if (!empty($idpMetadata['EntityAttributes']) && empty($this->getEntityAttributesDiff($this->entityAttributeWhitelist, $idpMetadata['EntityAttributes']))) {
            return true;
        }
        if (!empty($state['Attributes'][$this->attributeName]) && !empty(array_intersect($state['Attributes'][$this->attributeName], $this->entitlementWhitelist))) {
            return true;
        }
        return false;
    }


    private function getEntityAttributesDiff($array1, $array2)
    {
        $diff = array();
        foreach ($array1 as $key => $value) {
            if (empty($array2[$key]) || !is_array($array2[$key])) {
                $diff[$key] = $value;
            } else {
                $new_diff = array_diff($value, $array2[$key]);
                if (!empty($new_diff)) {
                    $diff[$key] = $new_diff;
                }
            }
        }
        return $diff;
    }
}
