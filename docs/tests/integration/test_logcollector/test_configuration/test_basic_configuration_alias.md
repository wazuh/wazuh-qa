# Test basic configuration - Alias
## Overview 

Check if `wazuh-logcollector` , or `wazuh-agent` in Windows system, uses provided alias values.

## Objective

- To confirm  the `alias` option works correctly.
- To confirm API response is equal to set configuration.

## General info

|Tier | Number of tests | Time spent |
|:--:|:--:|:--:|
| 0 | 2 | 54s |

## Expected behavior

- Fail if `wazuh-logcollector` or `wazuh-agent` does not show command result using alias value.
- Fail if API response is different that Wazuh configuration.

## Code documentation

::: tests.integration.test_logcollector.test_configuration.test_basic_configuration_alias
