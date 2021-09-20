# Test logtest - cdb labels file

## Overview

Checks if modifying the configuration of the cdb list, by using its labels, takes
effect when opening new logtest sessions without having to reset the manager.

## Objective

- To confirm that, when adding a new cdb list file, the
new cdb list are correctly loaded when a new session of logtest is opened

## General info

|Tier | Total | Time spent |
| :--:| :--:  | :--:       |
| 0   |    1 |    8.4s  |

## Expected behavior

- Fail if `wazuh-analysisd` is not running
- Fail if `wazuh-analysisd` returns an error
- Fail if `wazuh-analysisd` does not match the corresponding cdb list

## Code documentation

::: tests.integration.test_logtest.test_ruleset_refresh.test_cdb_labels