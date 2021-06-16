# Test macos log process stop

## Overview 

Check `log stream` process has been killed when Wazuh agent stops.

## Objective

- To confirm that Wazuh stops `log stream` process when stops.

## General info

|Tier | Number of tests | Time spent |
|:--:|:--:|:--:|
| 0 | 1 | 40s |

## Expected behavior

- Fail if `log stream` process still running after `wazuh-agent` stops.


## Code documentation

::: tests.integration.test_logcollector.test_macos.test_macos_log_process_stop