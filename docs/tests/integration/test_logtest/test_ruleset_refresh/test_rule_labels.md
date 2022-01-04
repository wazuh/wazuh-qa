# Test logtest - rules labels

## Overview

Checks if modifying the configuration of the rules, by using its labels, takes
effect when opening new logtest sessions, without having to reset the manager.

## Objective

- To confirm that, when adding a new file in the default rules directory, the
new rules are correctly loaded when a new session of logtest is opened
- To confirm that, when adding a new custom rules directory, the new rules
are correctly loaded when a new session of logtest is opened
- To confirm that, when adding a new rules file, the new rules are correctly
loaded when a new session of logtest is opened
- To confirm that, when excluding a rules file, the rules are not loaded when a
new session of logtest is opened

## General info

|Tier | Total | Time spent |
| :--:| :--:  | :--:       |
| 0   |    4 |    2s  |

## Expected behavior

- Fail if `wazuh-analysisd` is not running
- Fail if `wazuh-analysisd` returns an error
- Fail if `wazuh-analysisd` does not match the corresponding rule
- Fail if `wazuh-analysisd` does match the rule when it should not (exclude)

## Code documentation

::: tests.integration.test_logtest.test_ruleset_refresh.test_rule_labels
