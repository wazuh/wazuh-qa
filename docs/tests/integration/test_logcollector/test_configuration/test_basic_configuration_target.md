# Test basic configuration - Reconnect time
## Overview 

Check if `wazuh-agent` fails using invalid `target` values and allows valid ones.

## Objective

- To confirm `target` option allows valid values.
- To confirm `wazuh-logcollector` and `wazuh-agent` fails when invalid `target` values are provided.
- To confirm the API response is equal to set configuration.

## General info

|Tier | Number of tests | Time spent |
|:--:|:--:|:--:|
| 0 | 11 | 14.5s |

## Expected behavior

- Fail if `wazuh-logcollector` or `wazuh-agent` and start correctly when invalid `target` values
  are provided.
- Fail if `wazuh-logcollector` or `wazuh-agent` fails when invalid `target` values are provided.
- Fail if API response is different from the Wazuh configuration.

## Code documentation

::: tests.integration.test_logcollector.test_configuration.test_basic_configuration_target
