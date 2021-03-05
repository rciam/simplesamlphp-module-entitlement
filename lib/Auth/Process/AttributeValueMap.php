<?php

namespace SimpleSAML\Module\entitlement\Auth\Process;

use SimpleSAML\Auth\ProcessingFilter;
use SimpleSAML\Logger;

/**
 * Filter to create target attribute based on value(s) in source attribute
 *
 * @author Martin van Es, m7
 * @package SimpleSAMLphp
 */

class AttributeValueMap extends ProcessingFilter
{
    /**
     * The name of the attribute we should assign values to (ie: the target attribute).
     */
    private $targetAttribute;

    /**
     * The name of the attribute we should create values from.
     */
    private $sourceAttribute;

    /**
     * The required $sourceAttribute values and target affiliations.
     */
    private $values = [];

    /**
     * Whether $sourceAttribute should be kept or not.
     */
    private $keep = false;

    /**
     * Whether $target attribute values should be replaced by new values or not.
     */
    private $replace = false;

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

        // parse configuration
        foreach ($config as $name => $value) {
            if (is_int($name)) {
                // check if this is an option
                if ($value === '%replace') {
                    $this->replace = true;
                } elseif ($value === '%keep') {
                    $this->keep = true;
                } else {
                    // unknown configuration option, log it and ignore the error
                    Logger::warning("AttributeValueMap: unknown configuration flag '" . var_export($value, true) . "'");
                }
                continue;
            }

            // set the target attribute
            if ($name === 'targetAttribute') {
                $this->targetAttribute = $value;
            }

            // set the source attribute
            if ($name === 'sourceAttribute') {
                $this->sourceAttribute = $value;
            }

            // set the values
            if ($name === 'values') {
                $this->values = $value;
            }
        }

        // now validate it
        if (!is_string($this->sourceAttribute)) {
            throw new Exception("AttributeValueMap: 'sourceAttribute' configuration option not set.");
        }
        if (!is_string($this->targetAttribute)) {
            throw new Exception("AttributeValueMap: 'targetAttribute' configuration option not set.");
        }
        if (!is_array($this->values)) {
            throw new Exception("AttributeValueMap: 'values' configuration option is not an array.");
        }
    }


    /**
     * Apply filter.
     *
     * @param array &$request The current request
     */
    public function process(&$request)
    {
        Logger::debug('Processing the AttributeValueMap filter.');

        assert(is_array($request));
        assert(array_key_exists('Attributes', $request));
        $attributes = &$request['Attributes'];

        if (!array_key_exists($this->sourceAttribute, $attributes)) {
            // the source attribute does not exist, nothing to do here
            return;
        }

        $sourceAttribute = $attributes[$this->sourceAttribute];
        $targetValues = [];

        if (is_array($sourceAttribute)) {
            foreach ($this->values as $value => $values) {
                if (!is_array($values)) {
                    $values = [$values];
                }
                if (count(array_intersect($values, $sourceAttribute)) > 0) {
                    Logger::debug("AttributeValueMap: intersect match for '$value'");
                    $targetValues[] = $value;
                }
            }
        }

        if (count($targetValues) > 0) {
            if ($this->replace || !array_key_exists($this->targetAttribute, $attributes)) {
                $attributes[$this->targetAttribute] = $targetValues;
            } else {
                $attributes[$this->targetAttribute] = array_unique(array_merge(
                    $attributes[$this->targetAttribute],
                    $targetValues
                ));
            }
        }

        if (!$this->keep) {
            // no need to keep the source attribute
            unset($attributes[$this->sourceAttribute]);
        }
    }
}
