# Test syslog when no allowed ip address is provided

## Overview

Check if `wazuh-remoted` fails using syslog `connection` if no `allowed_ips` value is provided.

## Objective

To confirm `wazuh-remoted` fails when no `allowed_ips` are provided in syslog connection.

## General info

|Tier | Number of tests | Time spent |
|:--:|:--:|:--:|
| 0 | 1 | 3s |

## Expected behavior

- Fail if remoted start correctly.
- Fail if remoted debug does not show expected error output (error|critical).

## Code documentation

::: tests.integration.test_remoted.test_configuration.test_basic_configuration_syslog_no_allowed_ips
