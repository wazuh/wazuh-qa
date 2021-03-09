# Test invalid allowed ip address

## Overview 

Check if `wazuh-remoted` fails using invalid `allowed-ips` values and shows the expected error message to inform about it.

## Objective

To confirm `allowed-ips` option does not allow invalid values.

## General info

|Tier | Number of tests | Time spent |
|:--:|:--:|:--:|
| 0 | 4 | 8s |

## Expected behaviour

- Fail if remoted start correctly.
- Fail if remoted debug does not show expected error output (error|critical).

## Code documentation

::: tests.integration.test_remoted.test_configuration.test_basic_configuration_syslog_allowed_ips_invalid
