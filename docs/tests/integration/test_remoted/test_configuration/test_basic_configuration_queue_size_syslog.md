# Test queue size with syslog connection

## Overview 

Check if `wazuh-remoted` fails using valid `queue_size` along with `syslog` connection.

## Objective

To confirm that `wazuh-remoted` fails when `queue_size` tag is used at the same time that `syslog` connection.

## General info

|Tier | Number of tests | Time spent |
|:--:|:--:|:--:|
| 0 | 1 | 2 |

## Expected behaviour

- Fail if remoted start correctly.
- Fail if remoted debug does not show expected error output (error|critical).

## Code documentation

::: tests.integration.test_remoted.test_configuration.test_basic_configuration_ipv6
