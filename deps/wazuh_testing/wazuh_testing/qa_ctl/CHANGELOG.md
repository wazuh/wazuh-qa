# Change Log
All notable changes to this tool will be documented in this file.

## [v0.3.1] - 2022-03-07

### Added

- Added new parameters related to the run method. ([#2640](https://github.com/wazuh/wazuh-qa/pull/2640))


### Changed

- Changed how the tool uses `qa-docs`. ([#2640](https://github.com/wazuh/wazuh-qa/pull/2640))


## [v0.3] - 2021-12-10

### Added

- Added new module to be able to launch custom ansible tasks with `qa-ctl`.
- Added new methods to avoid the SSH fingerprint check ansible error.
- Added generation of independent configuration blocks for instance and task deployment.
- Added CentOS 7 support.
### Changed

- Improved modularization of functions for reading data from ansible instances.

### Fixed

- Fixed some typos in qa-ctl logs.
- Fixed some uses of UNIX libraries in `file` module under Windows.


## [v0.2] - 2021-11-05

### Added
- Added operating systems validation for specified OS in tests ([#2168](https://github.com/wazuh/wazuh-qa/pull/2168))
- Added Windows testing support in `qa-ctl` ([#2152](https://github.com/wazuh/wazuh-qa/pull/2152))
- Updated `qa-docs` usage in `qa-ctl` ([#2081](https://github.com/wazuh/wazuh-qa/pull/2081))
- Added `--os` parameter to specify the systems where to launch the tests ([#2064](https://github.com/wazuh/wazuh-qa/pull/2064))
- Added no-validation flag for `qa-ctl` docker run on windows ([#2028](https://github.com/wazuh/wazuh-qa/pull/2028))
- Added documentation tests validation precondition for automatic mode ([#2023](https://github.com/wazuh/wazuh-qa/issues/2023))


### Changed
- Updated `JSON Schema validator` ([#2164](https://github.com/wazuh/wazuh-qa/issues/2164))
- Removed `pytest` error traceback test results ([#2156](https://github.com/wazuh/wazuh-qa/pull/2156))
- Updated `local internal options` configutation of Wazuh ([#2102](https://github.com/wazuh/wazuh-qa/pull/2102))
- Replaced `git clone` usage for direct downloads ([#2046](https://github.com/wazuh/wazuh-qa/pull/2046))
- Changed `GitHub API requests` with `checks on resource URLs` for qa-ctl parameter validations ([#2033](https://github.com/wazuh/wazuh-qa/pull/2033))
- Renamed `qa-ctl` temporary files directory ([#2029](https://github.com/wazuh/wazuh-qa/pull/2029))
- Updated `qa-ctl` help menu information ([#2026](https://github.com/wazuh/wazuh-qa/pull/2026))


### Fixed
- Fixed `Docker` issues for `qa-ctl` (manual mode) in `Windows` ([#2147](https://github.com/wazuh/wazuh-qa/pull/2147))
- Fixed `qa-ctl` configuration path separators for `windows` ([#2036](https://github.com/wazuh/wazuh-qa/pull/2036))


## [v0.1]


### Added
  - Added new folder level for temporary files ([#1993](https://github.com/wazuh/wazuh-qa/pull/1993))
  - Added new implementation for generating `qa-ctl` configuration paths ([#1982](https://github.com/wazuh/wazuh-qa/pull/1982))
  - Added skip execution stages options for `qa-ctl` tool ([#1976](https://github.com/wazuh/wazuh-qa/pull/1976))
  - Added option `--qa-branch` for `qa-ctl` tool ([#1974](https://github.com/wazuh/wazuh-qa/pull/1974))
  - Added `qa-ctl` native support for Windows ([#1961](https://github.com/wazuh/wazuh-qa/pull/1961))
  - Added debug mode and unified logs of  every section. ([#1924](https://github.com/wazuh/wazuh-qa/pull/1924))
  - Added new tool for generating `YAML` configuration file automatically. ([#1892](https://github.com/wazuh/wazuh-qa/pull/1892))
  - Added new documentation for `qa-ctl` module ([#1837](https://github.com/wazuh/wazuh-qa/pull/1837))
  - Added new tool for generating S3 package links ([#1828](https://github.com/wazuh/wazuh-qa/pull/1828))
  - Added documentation for `qa-ctl` modules ([#1805](https://github.com/wazuh/wazuh-qa/pull/1805))
  - Added show test results in stdout with Logging module ([#1795](https://github.com/wazuh/wazuh-qa/pull/1795))
  - Added `qa-ctl` Logging module ([#1791](https://github.com/wazuh/wazuh-qa/pull/1791))
  - Added wazuh installation packages via S3 option ([#1781](https://github.com/wazuh/wazuh-qa/pull/1781))
  - Renamed all `qa-ctl` modules using the `snake_case` format ([#1781](https://github.com/wazuh/wazuh-qa/pull/1781))
  - Added delete all temporary files created during execution option ([#1781](https://github.com/wazuh/wazuh-qa/pull/1781))
  - Added parallelization implementation for all the modules of `qa-ctl` ([#1770](https://github.com/wazuh/wazuh-qa/pull/1770))
  - Modified JSON Schema file validator for validating new fields ([#1764](https://github.com/wazuh/wazuh-qa/pull/1764)) ([#1781](https://github.com/wazuh/wazuh-qa/pull/1781))
  - Restructure `dockerfiles` directory organization ([#1764](https://github.com/wazuh/wazuh-qa/pull/1764))
  - Added Amazon Linux and Ubuntu Focal dockerfiles for Docker image generation ([#1760](https://github.com/wazuh/wazuh-qa/pull/1760))
  - Separate Test module and Provisioning module logic ([#1750](https://github.com/wazuh/wazuh-qa/pull/1750))
  - Added JSON schema for validating `YAML` configuration files ([#1744](https://github.com/wazuh/wazuh-qa/pull/1744))
  - Added a script for launching all the `qa-ctl` functionalities and modules ([#1696](https://github.com/wazuh/wazuh-qa/pull/1696))
  - Added provisioning module for `qa-ctl` with Ansible ([#1683](https://github.com/wazuh/wazuh-qa/pull/1683))
  - Added Infrastructure module ([#1679](https://github.com/wazuh/wazuh-qa/pull/1679)).
  - Added implementation to automate the Wazuh provisioning and the QA framework with Ansible ([#1676](https://github.com/wazuh/wazuh-qa/pull/1676))
  - Added testing module for `qa-ctl` ([#1675](https://github.com/wazuh/wazuh-qa/pull/1675))
  - Added vagrant wrapper to automate the VM creation for `qa-ctl` ([#1673](https://github.com/wazuh/wazuh-qa/pull/1673))
  - Added docker wrapper to automate container creation for `qa-ctl`([#1672](https://github.com/wazuh/wazuh-qa/pull/1672))
  - Added instance & InstanceHandler classes for provisioning module of `qa-ctl`([#1671](https://github.com/wazuh/wazuh-qa/pull/1671))
  - Added ansible modules for `qa-ctl` ([#1632](https://github.com/wazuh/wazuh-qa/pull/1632))
