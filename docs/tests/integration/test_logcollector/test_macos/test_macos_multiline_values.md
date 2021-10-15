# Test macOS multi-line values
## Overview 

Check if `wazuh-logcollector` correctly gathers unified logging system events when working with `multi-line` logs.

## Objective

- To confirm Wazuh macOS agent gather correctly unified logging system events with specific format value.


## General info

|Tier | Total | Time spent |
| :--:| :--:  | :--:       |
| 0   |    1  |     29s    |


## Expected behavior
- Fail if `wazuh-logcollector` does not gather generated unified logging system `multi-line` event or does not send it to the manager.

## Code documentation

::: tests.integration.test_logcollector.test_macos.test_macos_multiline_values
