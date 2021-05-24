# Test Log format values
## Overview 

Check if `wazuh-logcollector` or `wazuh-agent` in Windows agent, allows valid `log_format` values with content values valid for the 
log monitoring and fails using invalid content with valid `log_format` values.

## Objective

- To confirm Wazuh allows all possible `log_format` valid values.
- To confirm `wazuh-logcollector`, or `wazuh-agent` fails when valid `log_format` with content files invalid.

## General info

|Tier | Total | Time spent |
| :--:| :--:  | :--:       |
| 0   |    17 |    3m40s   |


## Expected behavior

- Fail if `wazuh-logcollector` or `wazuh-agent` allows invalid `log_format` content values for log monitoring.
- Fail if `wazuh-logcollector` or `wazuh-agent` does not start correctly using valid `log_format` values.

## Code documentation

::: tests.integration.test_logcollector.test_log_format.test_log_format_values
