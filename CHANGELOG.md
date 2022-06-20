# Changelog
  
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [v1.0.1] - 2022-06-20

### Fixed

- Bug in capability evaluation when no entity attribute whitelist is configured


## [v1.0.0] - 2021-03-01

This version is compatible with [SimpleSAMLphp v1.14](https://simplesamlphp.org/docs/1.14/simplesamlphp-changelog)

### Added

- Authproc filter `entitlement:AddCapability` for evaluating the resource capabilities of the authenticating user
