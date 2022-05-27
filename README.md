# simplesamlphp-module-entitlement

A suite of SimpleSAMLphp authentication processing filters for processing attributes expressing group or resource entitlements.

## AttributeValueMap
Filter that creates a target attribute based on one or more value(s) in source attribute.

Besides the mapping of source values to target values, the filter has the following options: * %replace can be used to replace all existing values in target with new ones (any existing values will be lost) * %keep can be used to keep the source attribute, otherwise it will be removed.

```php
'authproc' => [
    ... 
    201 => [
        'class' => 'entitlement:AttributeValueMap',
        'sourceAttribute' => 'eduPersonEntitlement', // or 'urn:oid:1.3.6.1.4.1.5923.1.1.1.7',
        'targetAttribute' => 'eduPersonEntitlement', // or 'urn:oid:1.3.6.1.4.1.5923.1.1.1.7',
        'values' => [
            'urn:mace:example.org:group:vo.example.org:role=member#foo.example.org' => [
                'urn:mace:idp.example.org:group:another.vo.example.org:role=member#bar.example.org',
            ],
            'urn:mace:example.org:group:vo.example.org:role=vm_operator#foo.example.org' => [
                'urn:mace:idp.example.org:group:another.vo.example.org:role=vm_operator#bar.example.org',
            ],
        ],
        '%keep',
    ],
```

## FederatedAttributeValueMap
Filter that creates a target attribute based on one or more value(s) in source attribute per IdP entity ID.

Besides the mapping of source values to target values, the filter has the following options: * %replace can be used to replace all existing values in target with new ones (any existing values will be lost) * %keep can be used to keep the source attribute, otherwise it will be removed.

```php
'authproc' => [
    ... 
    201 => [
        'class' => 'entitlement:FederatedAttributeValueMap',
        'authnAuthorityAttribute' => 'authnAuthority', //Optional, defaults to authnAuthority
        'idpValueMap' => [
            'idp1.example.org' => [
                'sourceAttribute' => 'urn:oid:1.3.6.1.4.1.5923.1.1.1.7',
                'targetAttribute' => 'urn:oid:1.3.6.1.4.1.5923.1.1.1.7',
                'values' => [
                    'urn:mace:example.org:group:vo.example.org:role=member#foo.example.org' => [
                    'urn:mace:idp.example.org:group:another.vo.example.org:role=member#bar.example.org',
                    ],
                    'urn:mace:example.org:group:vo.example.org:role=vm_operator#foo.example.org' => [
                    'urn:mace:idp.example.org:group:another.vo.example.org:role=vm_operator#bar.example.org',
                    ],
                ],
                '%keep',
            ],
            'idp2.example.org' => [
                'sourceAttribute' => 'urn:oid:1.3.6.1.4.1.5923.1.1.1.7',
                'targetAttribute' => 'urn:oid:1.3.6.1.4.1.5923.1.1.1.7',
                'values' => [],
            ],
        ],
    ],
```
## Compatibility matrix

This table matches the module version with the supported SimpleSAMLphp version.

| Module |  SimpleSAMLphp |
|:------:|:--------------:|
| v1.x   | v1.14          |
| v2.x   | v1.17+         |

## License

Licensed under the Apache 2.0 license, for details see `LICENSE`.
