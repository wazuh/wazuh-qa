# Test basic configuration - Age
## Overview 

Check if `wazuh-logcollector` or `wazuh-agent` for Windows agent, fails using invalid `age` values and,
allow valid values.

## Objective

- To confirm `age` option allows valid values.
- To confirm `wazuh-logcollector` and `wazuh-agent` fails when invalid age values are provided.
- To confirm the API response is equal to set configuration.

## General info

|Tier | Number of tests | Time spent |
|:--:|:--:|:--:|
| 0 | 11 | 16.4s |

## Expected behavior

- Fail if `wazuh-logcollector` or `wazuh-agent` starts correctly when invalid age values are provided.
- Fail if `wazuh-logcollector` or `wazuh-agent` does not start correctly when valid age values are provided.
- Fail if the API response is different from the Wazuh configuration.

## Code documentation

::: tests.integration.test_logcollector.test_configuration.test_basic_configuration_age