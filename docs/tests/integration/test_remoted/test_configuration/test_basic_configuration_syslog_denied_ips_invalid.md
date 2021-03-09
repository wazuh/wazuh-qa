# Test invalid denied ip address

## Overview 

Check if `wazuh-remoted` fails using invalid `denied-ips` values and shows the expected error message to inform about it.

## Objective

To confirm `denied-ips` option does not allow invalid values.

## General info

|Tier | Number of tests | Time spent |
|:--:|:--:|:--:|
| 0 | 3 | 8s |

## Expected behaviour

- Fail if remoted start correctly.
- Fail if remoted debug does not show expected error output (error|critical).

## Code documentation

::: tests.integration.test_remoted.test_configuration.test_basic_configuration_syslog_denied_ips_invalid
