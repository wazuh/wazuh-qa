# Test macOS file status when no macos
## Overview 

Checks that `wazuh-logcollector` does not store and removes, if exists, previous 
"macos"-formatted localfile data in the file_status.json

## Objective

- Confirm that, given a file_status.json that contains a valid combination of 
"settings" and "timestamp" of "macos", when starting an agent that has no 
"macos" localfile configured on its ossec.conf file, it should happen that, when
file_status.json is updated after a certain time, no "macos" status should 
remain stored on the status file.

## General info

|Tier | Total | Time spent |
| :--:| :--:  | :--:       |
| 0   |    1 |    50s  |


## Expected behavior

- Fail if `wazuh-logcollector` stores "macos"-formatted localfile data in the status file `status_file.json`.


## Code documentation

::: tests.integration.test_logcollector.test_macos.test_macos_file_status_when_no_macos
