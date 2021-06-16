# Test macos log process stop suddenly

## Overview 

Check that `wazuh-logcollector` alerts with an error message when `log stream` process is killed.

## Objective

- To confirm that `wazuh-logcollector` alerts with an error message when `log stream` process is killed.

## General info

|Tier | Number of tests | Time spent |
|:--:|:--:|:--:|
| 0 | 1 | 40s |

## Expected behavior

- Fail if the expected error message has not been generated

## Code documentation

::: tests.integration.test_logcollector.test_macos.test_macos_log_process_stop_suddenly