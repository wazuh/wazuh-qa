# Test invalid port

## Overview 

Check if `wazuh-remoted` fails using invalid `port` values and shows the expected error message to inform about it.

## Objective

To confirm `port` option does not allow invalid values.

## General info

|Tier | Number of tests | Time spent |
|:--:|:--:|:--:|
| 0 | 1 | 2.5s |

## Expected behavior

- Fail if remoted start correctly.
- Fail if remoted debug does not show expected error output (error|critical).

## Code documentation

::: tests.integration.test_remoted.test_configuration.test_basic_configuration_connection_invalid_port
