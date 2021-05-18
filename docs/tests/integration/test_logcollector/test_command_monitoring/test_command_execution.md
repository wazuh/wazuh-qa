# Test command execution

## Overview 

Check if the Wazuh runs correctly by executing different commands with special characteristics 
and check if the debug logs are displayed correctly when the test commands are executed.

## Objective

- To confirm `command` option works correctly with different types of commands.
- To confirm that debug logs are generated correctly.

## General info

|Tier | Number of tests | Time spent |
|:--:|:--:|:--:|
| 0 | 44 | 2m49s |

## Expected behavior

- Fail if it is not possible to verify that the command is executed correctly.
- Fail if debug logs are not displayed when executing the command.

## Code documentation

::: tests.integration.test_logcollector.test_command_monitoring.test_command_execution