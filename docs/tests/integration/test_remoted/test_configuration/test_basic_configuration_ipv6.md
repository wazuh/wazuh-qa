# Test valid ipv6

## Overview 

Check if `wazuh-remoted` correctly start using valid `ipv6` values.

## Objective

To confirm `ipv6` can be configured to `yes` without errors. In case of `secure` connection, IPv4 should be used.

## General info

|Tier | Number of tests | Time spent |
|:--:|:--:|:--:|
| 0 | 2 | 4 |

## Expected behavior

- Fail if remoted does not start correctly.
- Fail if remoted does not show expected warning if use secure connection with ipv6 with value `yes`.
- Fail if API query `{protocol}://{host}:{port}/manager/configuration?section=remote` doesn't match the 
  introduced configuration on ossec.conf.

## Code documentation

::: tests.integration.test_remoted.test_configuration.test_basic_configuration_ipv6
