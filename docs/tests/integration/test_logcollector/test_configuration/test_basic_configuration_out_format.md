# Test basic configuration - Out format
## Overview 

Check if `wazuh-agent` fails using invalid `out-format` values and allows valid `out-format` 
values.

## Objective

- To confirm `out-format` option allows valid `out-format` values.
- To confirm `wazuh-logcollector` and `wazuh-agent` fails when invalid `out-format` 
  values are provided.
- To confirm the API response is equal to set configuration.

## General info

|Tier | Number of tests | Time spent |
|:--:|:--:|:--:|
| 0 | 11 | 1m5s |

## Expected behavior

- Fail if `wazuh-logcollector` or `wazuh-agent` start correctly when invalid 
  `out-format` values are provided.
- Fail if `wazuh-logcollector` or `wazuh-agent` does not start correctly when invalid 
  `out-format` values are provided.
- Fail if the API response is different from the Wazuh configuration.

## Code documentation 

::: tests.integration.test_logcollector.test_configuration.test_basic_configuration_out_format
