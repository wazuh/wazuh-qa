# Test basic configuration - Label
## Overview 

Check if `wazuh-logcollector` or `wazuh-agent` for Windows agent allows valid label values.

## Objective

- To confirm Wazuh configuration allows `label` option.
- To confirm the API response is equal to set configuration.

## General info

|Tier | Number of tests | Time spent |
|:--:|:--:|:--:|
| 0 | 9 | 19.19s |

## Expected behavior

- Fail if `wazuh-logcollector` or `wazuh-agent` allows valid label values.
- Fail if the API response is different from the Wazuh configuration.

## Code documentation

::: tests.integration.test_logcollector.test_configuration.test_basic_configuration_label
