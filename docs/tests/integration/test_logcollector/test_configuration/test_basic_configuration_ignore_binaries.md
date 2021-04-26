# Test basic configuration - Ignore binaries
## Overview 

Check if `wazuh-logcollector`, or `wazuh-agent` for Windows agents, fails using invalid `ignore_binaries` 
values and allows valid `ignore_binaries` value.

## Objective

- To confirm `ignore_binaries` option allows valid values.
- To confirm `wazuh-logcollector` and `wazuh-agent` fails when invalid `ignore_binaries` values are provided.
- To confirm the API response is equal to set configuration.

## General info

|Tier | Number of tests | Time spent |
|:--:|:--:|:--:|
| 0 | 11 | 8.3s |

## Expected behavior

- Fail if `wazuh-logcollector` or `wazuh-agent` starts correctly when invalid `ignore_binaries` values 
  are provided.
- Fail if `wazuh-logcollector` or `wazuh-agent` does not start correctly when invalid `ignore_binaries` 
  values are provided.
- Fail if the API response is different from the Wazuh configuration.

## Code documentation

::: tests.integration.test_logcollector.test_configuration.test_basic_configuration_ignore_binaries
