# Change Log
All notable changes to this tool will be documented in this file.

## [v0.1]

### Added
  - Added new tool for generating `YAML` configuration file automatically. ([#1828](https://github.com/wazuh/wazuh-qa/pull/1892))
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
