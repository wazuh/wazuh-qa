# Test logtest - remove session

## Overview

Check if `wazuh-logtest` correctly detects and removes the sessions under
pre-defined scenarios.

## Objective

- Confirm that `wazuh-logtest` correctly handles the sessions removals.

## General info

|Tier | Total | Time spent |
| :--:| :--:  | :--:       |
| 0   |    9 |    1s  |

## Expected behavior

- Fail if the session removal attempt does not produce the expected result message.

## Code documentation

::: tests.integration.test_logtest.test_remove_session.test_remove_session
