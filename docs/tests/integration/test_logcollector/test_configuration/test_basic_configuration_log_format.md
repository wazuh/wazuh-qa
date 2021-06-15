# Test basic configuration - Log format
## Overview 

Check if `wazuh-logcollector` or `wazuh-agent` in Windows agent, allows valid `log_format` values for 
log monitoring and fails using invalid `log_format` values.

## Objective

- To confirm Wazuh allows all possible `log_format` valid values.
- To confirm `wazuh-logcollector`, or `wazuh-agent` fails when invalid `log_format` is provided.
- To confirm the API response is equal to set configuration.
- To confirm `wazuh-logcollector` only allow one macOS configuration block can be set.
- To confirm `wazuh-logcollector` accept invalid values for `location` option when macos `log_format` is set.
- To confirm `wazuh-logcollector` uses default macos `location` value when it is not configured.

## General info

|Tier | Number of tests | Time spent |
|:--:|:--:|:--:|
| 0 | 4 | 39.8s |

## Expected behavior

- Fail if `wazuh-logcollector` or `wazuh-agent` allows invalid `log_format` values for log monitoring.
- Fail if `wazuh-logcollector` or `wazuh-agent` does not start correctly using valid `log_format` values.
- Fail if the API response is different from the Wazuh configuration.
- Fail if `wazuh-logcollector` does not fails when more than one macos block is set.
- Fail if `wazuh-logcollector` does not show a warning message when no `location` value is provided for macos 
  `log_format`.
- Fail if `wazuh-logcollector` does not show a warning message when invalid `location` value is provided for 
  macos `log_format`.

## Code documentation

::: tests.integration.test_logcollector.test_configuration.test_basic_configuration_log_format
