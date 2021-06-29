# Test basic configuration - Exclude
## Overview 

Check if `wazuh-logcollector`, or `wazuh-agent` in Windows agent, allows valid exclude values for 
log monitoring.

## Objective

- To confirm `exclude` option is used correctly.
- To confirm the API response is equal to the set configuration.

## General info

|Tier | Number of tests | Time spent |
|:--:|:--:|:--:|
| 0 | 4 | 6.6s |

## Expected behavior

- Fail if `wazuh-logcollector` or `wazuh-agent` allows valid exclude values for command monitoring.
- Fail if the API response is different from the Wazuh configuration.

## Code documentation

::: tests.integration.test_logcollector.test_configuration.test_basic_configuration_exclude
