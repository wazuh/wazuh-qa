# Test macOS - File status basic

## Overview

Checks if `wazuh-logcollector` correctly generates the `file_status.json` file used by `only future events`.

## Objective

- To confirm that the Wazuh macOS agent generates a valid status file (`file_status.json`)
that can be used at the next startup of Wazuh-Logcollector

## General info

|Tier | Total | Time spent |
| :--:| :--:  | :--:       |
| 0   |    2 |    105s  |

## Expected behavior

- Fail if `wazuh-logcollector` does not gather generated unified logging system event or does not send it to the manager
- Fail if `wazuh-logcollector` does not create the status file `status_file.json`
- Fail if `wazuh-logcollector` saves incorrectly formatted, or invalid data in the status file `status_file.json`.

## Code documentation

::: tests.integration.test_logcollector.test_macos.test_macos_file_status_basic
