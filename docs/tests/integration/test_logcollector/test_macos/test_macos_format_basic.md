# Test macOS format basic
## Overview 

Check if `wazuh-logcollector` gather correctly unnified logging system events.

## Objective

- To confirm Wazuh macOS agent gather correctly unnified logging system events.

## General info

|Tier | Total | Time spent |
| :--:| :--:  | :--:       |
| 0   |    2 |    54s  |


## Expected behavior

- Fail if `wazuh-logcollector` does not gather generated unnified logging system event or does not send it to the manager

## Code documentation

::: tests.integration.test_logcollector.test_macos.test_macos_format_basic
