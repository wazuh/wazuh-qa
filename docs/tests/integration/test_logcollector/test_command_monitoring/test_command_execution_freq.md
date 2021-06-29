# Test command execution freq

## Overview 

Check if the Wazuh run commands correctly with the specified command monitoring option `frequency`.

## Objective

To confirm `frequency` option works correctly with different time intervals.

## General info

|Tier | Number of tests | Time spent |
|:--:|:--:|:--:|
| 0 | 8 | 3m28s |

## Expected behavior

- Fail if the command is executed before the established interval.

## Code documentation

::: tests.integration.test_logcollector.test_command_monitoring.test_command_execution_freq
