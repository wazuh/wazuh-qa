# Test logtest - invalid rules syntax

## Overview

Check if `wazuh-logtest` correctly detects and handles errors when processing a rules file.

## Objective

- Confirm that `wazuh-logtest` retrieves errors when the loaded rules are invalid.

## General info

|Tier | Total | Time spent |
| :--:| :--:  | :--:       |
| 0   |    15 |    9s  |

## Expected behavior

- Fail if `wazuh-logtest` does not retrieve an error when it should.

## Code documentation

::: tests.integration.test_logtest.test_invalid_rule_decoders_syntax.test_invalid_rules_syntax
