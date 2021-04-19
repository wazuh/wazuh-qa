# Test basic configuration - Location
## Overview 

Check if `wazuh-logcollector`, or `wazuh-agent` in Windows agent, allows valid `location` values for 
log monitoring.

## Objective

- To confirm Wazuh allows all possible `location` valid values.
- To confirm API response is equal to set configuration.

## General info

|Tier | Number of tests | Time spent |
|:--:|:--:|:--:|
| 0 | 4 | 10.5s |

## Expected behavior

- Fail if `wazuh-logcollector` or `wazuh-agent` allows valid `location` values for log monitoring.
- Fail if API response is different that Wazuh configuration.

## Code documentation

::: tests.integration.test_logcollector.test_configuration.test_basic_configuration_location
