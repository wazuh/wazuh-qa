# Test query for macos format

## Overview 

Check if `query` option for `wazuh-logcollector` works correctly for macos unified logging 
system format (ULS).

## Objective

- To confirm that `wazuh-logcollector` gather all ULS events that fulfill `query` conditions.
- To confirm that `wazuh-logcollector` does not gather events that not fulfill `query` conditions.

## General info

|Tier | Number of tests | Time spent |
|:--:|:--:|:--:|
| 0 | 72 | 1h30m |

## Expected behavior

- Fail if `wazuh-logcollector` does not read correctly macOS ULS log stream.
- Fail if `wazuh-logcollector` does not gather events that fulfill `query` condition.
- Fail if `wazuh-logcollector` gather events that not fulfill `query` conditions.

## Code documentation

::: tests.integration.test_logcollector.test_macos.test_macos_format_query