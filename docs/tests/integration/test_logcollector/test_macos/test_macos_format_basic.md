# Test macOS format basic
## Overview 

Check if `wazuh-logcollector` correctly gathers unified logging system events.

## Objective

- To confirm Wazuh macOS agent gather correctly unified logging system events.

## General info

|Tier | Total | Time spent |
| :--:| :--:  | :--:       |
| 0   |    2 |    54s  |


## Expected behavior

- Fail if `wazuh-logcollector` does not gather generated unified logging system event or does not send it to the manager

## Code documentation

::: tests.integration.test_logcollector.test_macos.test_macos_format_basic
