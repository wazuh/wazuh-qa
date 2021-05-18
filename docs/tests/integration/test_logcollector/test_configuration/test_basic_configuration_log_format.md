# Test basic configuration - Log format
## Overview 

Check if `wazuh-logcollector` or `wazuh-agent` in Windows agent, allows valid `log_format` values for 
log monitoring and fails using invalid `log_format` values.

## Objective

- To confirm Wazuh allows all possible `log_format` valid values.
- To confirm `wazuh-logcollector`, or `wazuh-agent` fails when invalid `log_format` is provided.
- To confirm the API response is equal to set configuration.

## General info

|Tier | Number of tests | Time spent |
|:--:|:--:|:--:|
| 0 | 4 | 39.8s |

## Expected behavior

- Fail if `wazuh-logcollector` or `wazuh-agent` allows invalid `log_format` values for log monitoring.
- Fail if `wazuh-logcollector` or `wazuh-agent` does not start correctly using valid `log_format` values.
- Fail if the API response is different from the Wazuh configuration.

## Code documentation

::: tests.integration.test_logcollector.test_configuration.test_basic_configuration_log_format
