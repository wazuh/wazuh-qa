# Test basic configuration - Command
## Overview 

Check if `wazuh-logcollector` or `wazuh-agent` for Windows agent, allows valid command values 
for command monitoring.

## Objective

- To confirm `command` option is used correctly.
- To confirm the API response is equal to set configuration.

## General info

|Tier | Number of tests | Time spent |
|:--:|:--:|:--:|
| 0 | 9 | 1m3.3s |

## Expected behavior

- Fail if `wazuh-logcollector` or `wazuh-agent` allows valid command for command monitoring.
- Fail if the API response is different from the Wazuh configuration.

## Code documentation

::: tests.integration.test_logcollector.test_configuration.test_basic_configuration_command
