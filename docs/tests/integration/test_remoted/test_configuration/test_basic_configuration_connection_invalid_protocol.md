# Test invalid protocol

## Overview 

Check if `wazuh-remoted` correctly start using invalid `protocol` values.

## Objective

To confirm that `protocol` option allow multiple values and works correctly when one or multiple of them are not valid.

## General info

|Tier | Number of tests | Time spent |
|:--:|:--:|:--:|
| 0 | 8 | 20s |

## Expected behavior

- Fail if remoted does not start correctly.
- Fail if remoted does not use TCP in case of every value in the `protocol` option is invalid.
- Fail if remoted does not show expected warning if use more than one protocol for syslog connection.
- Fail if API query `{protocol}://{host}:{port}/manager/configuration?section=remote` doesn't match 
  the introduced configuration on ossec.conf.

## Code documentation

::: tests.integration.test_remoted.test_configuration.test_basic_configuration_connection_invalid_protocol
