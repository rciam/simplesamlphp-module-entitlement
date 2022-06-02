<?php

namespace SimpleSAML\Module\entitlement\Auth\Process;

use SimpleSAML\Auth\ProcessingFilter;
use SimpleSAML\Module\entitlement\Auth\Process\AttributeValueMap;
use SimpleSAML\Error;
use SimpleSAML\Logger;

/**
 * Filter to create target attribute based on value(s) in source attribute
 *
 * Example config
 * 201 => [
 *     'class' => 'entitlement:FederatedAttributeValueMap',
 *     'authnAuthorityAttribute' => 'authnAuthority', //Optional, defaults to authnAuthority
 *     'idpValueMap' => [
 *        'idp1.example.org' => [
 *             'sourceAttribute' => 'urn:oid:1.3.6.1.4.1.5923.1.1.1.7',
 *             'targetAttribute' => 'urn:oid:1.3.6.1.4.1.5923.1.1.1.7',
 *             'values' => [
 *                 'urn:mace:egi.eu:group:vo.panosc.eu:role=vm_operator#aai.egi.eu' => [
 *                    'urn:geant:eduteams.org:service:umbrellaid.org:group:umbrellaid#umbrellaid.org',
 *                  ],
 *                 'urn:mace:egi.eu:vo.eoscfuture-sp.panosc.eu:role=member#aai.egi.eu' => [
 *                    'urn:geant:eduteams.org:service:umbrellaid.org:group:umbrellaid:eosc-future:wp6#umbrellaid.org',
 *                  ],
 *                 'urn:mace:egi.eu:vo.eoscfuture-sp.panosc.eu:role=vm_operator#aai.egi.eu' => [
 *                    'urn:geant:eduteams.org:service:umbrellaid.org:group:umbrellaid:eosc-future:wp6#umbrellaid.org',
 *                  ],
 *             ],
 *             '%keep',
 *        ],
 *       'idp2.example.org' => [
 *            'sourceAttribute' => 'urn:oid:1.3.6.1.4.1.5923.1.1.1.7',
 *            'targetAttribute' => 'urn:oid:1.3.6.1.4.1.5923.1.1.1.7',
 *            'values' => [],
 *       ],
 *    ],
 * ],
 */

class FederatedAttributeValueMap extends ProcessingFilter
{
    /**
     * An array containing the IdPs that should have a specific configuration for mapping values.
     */
    private $idpValueMap;

    /**
     * A string that contains the name of the authnAuthority attribute
     */
    private $authnAuthorityAttribute = 'authnAuthority';

    /**
     * Initialize the filter.
     *
     * @param array $config Configuration information about this filter.
     * @param mixed $reserved For future use.
     * @throws \SimpleSAML\Error\Exception If the configuration is not valid.
     */
    public function __construct($config, $reserved)
    {
        parent::__construct($config, $reserved);

        assert(is_array($config));

        if (array_key_exists('authnAuthorityAttribute', $config)) {
            if (!is_string($config['authnAuthorityAttribute'])) {
                Logger::error(
                    "[federatedattributevaluemap] Configuration error: 'authnAuthorityAttribute' not an string");
                throw new \Exception(
                    "[federatedattributevaluemap] configuration error: 'authnAuthorityAttribute' not an string");
            }
            $this->authnAuthorityAttribute = $config['authnAuthorityAttribute'];
        }
        // parse configuration for idPs
        foreach ($config['idpValueMap'] as $name => $value) {
            $this->idpValueMap[$name] = new AttributeValueMap($value, $reserved);
        }

    }

    /**
     * Apply filter.
     *
     * @param array &$request The current request
     */
    public function process(&$request)
    {
        Logger::debug('Processing the FederatedAttributeValueMap filter.');

        assert(is_array($request));
        assert(array_key_exists('Attributes', $request));
        if(empty($request['Attributes'][$this->authnAuthorityAttribute][0])) {
            Logger::error(
                "[federatedattributevaluemap] process: ' . $this->authnAuthorityAttribute . ' value is empty
                 or does not exist at Attributes");
                 throw new Error\Error(
                    ['UNHANDLEDEXCEPTION', 'Ooops something went wrong.']
                );

        }
        $idpEntityID = $request['Attributes'][$this->authnAuthorityAttribute][0];

        if (array_key_exists($idpEntityID, $this->idpValueMap)) {  
            $this->idpValueMap[$idpEntityID]->mapAttributeValue($request['Attributes']);
        } else {
            Logger::debug('skipping FederatedAttributeValueMap filter for authnAuthority ' + $idpEntityID);    
        }
    }
}
