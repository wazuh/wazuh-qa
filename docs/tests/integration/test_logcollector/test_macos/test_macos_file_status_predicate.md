# Test macOS - File status predicate

## Overview

Checks that `wazuh-logcollector` does not store "macos"-formatted localfile data in `file_status.json`,
since its predicate is erroneous. Respective errors should be logged in the `ossec.log` file.

## Objective

- Confirm that, even when the Wazuh macOS agent generates a valid status file (`file_status.json`), there is no stored
data related to the "macos"-formatted localfile, even when a configuration block (with an erroneous predicate) is set.

## General info

|Tier | Total | Time spent |
| :--:| :--:  | :--:       |
| 0   |    2 |    30s  |

## Expected behavior

- Fail if `wazuh-logcollector` does not create the status file `status_file.json`
- Fail if `wazuh-logcollector` stores "macos"-formatted localfile data in the status file `status_file.json`.
- Fail if `wazuh-logcollector` does not log the errors related to `log stream` in the log file `ossec.log`.

## Code documentation

::: tests.integration.test_logcollector.test_macos.test_macos_file_status_predicate
