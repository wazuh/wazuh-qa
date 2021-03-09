# Test valid connection

## Overview 

Check if `wazuh-remoted` correctly start using valid `protocol` values.

## Objective

To confirm `protocol` option allows valid values.

## General info

|Tier | Number of tests | Time spent |
|:--:|:--:|:--:|
| 0 | 8 | 17 |

## Expected behaviour

- Fail if remoted does not start correctly.
- Fail if remoted does not show expected warning if use more than one protocol for syslog connection.
- Fail if API query `{protocol}://{host}:{port}/manager/configuration?section=remote` doesn't match the 
  introduced configuration on ossec.conf.

## Code documentation

::: tests.integration.test_remoted.test_configuration.test_basic_configuration_connection_valid
