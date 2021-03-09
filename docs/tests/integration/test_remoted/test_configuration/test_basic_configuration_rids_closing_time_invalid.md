# Test invalid rids closing time invalid

## Overview 

Check if `wazuh-remoted` fails using invalid `rids_closing_time` values and shows the expected 
error message to inform about it.

## Objective

To confirm `rids_closing_time` option does not allow invalid values.

## General info

|Tier | Number of tests | Time spent |
|:--:|:--:|:--:|
| 0 | 1 | 3s |

## Expected behaviour

- Fail if remoted start correctly.
- Fail if remoted debug does not show expected error output (error|critical).

## Code documentation

::: tests.integration.test_remoted.test_configuration.test_basic_configuration_rids_closing_time_invalid
