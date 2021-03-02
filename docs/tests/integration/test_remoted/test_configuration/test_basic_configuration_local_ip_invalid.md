# Test invalid local ip address

## Overview 

Check if `wazuh-remoted` fails using invalid `local_ip` values and shows the expected error message to inform about it.

## Objective

To confirm `local_ip` option does not allow invalid values.

## General info

|Tier | Number of tests | Time spent |
|:--:|:--:|:--:|
| 0 | 2 | 5s |

## Expected behavior

- Fail if remoted start correctly.
- Fail if remoted debug does not show expected error output (error|critical).

## Code documentation

::: tests.integration.test_remoted.test_configuration.test_basic_configuration_local_ip_invalid
