# Test valid local ip 

## Overview 

Check if `wazuh-remoted` correctly start using valid `local_ip` values.

## Objective

To confirm `local_ip` can be configured to any ip address of all available network interface.

## General info

|Tier | Number of tests | Time spent |
|:--:|:--:|:--:|
| 0 | 1 | 7 |

## Expected behaviour

- Fail if remoted does not start correctly.
- Fail if API query `{protocol}://{host}:{port}/manager/configuration?section=remote` doesn't match the introduced 
  configuration on ossec.conf.

## Code documentation

::: tests.integration.test_remoted.test_configuration.test_basic_configuration_local_ip_valid
