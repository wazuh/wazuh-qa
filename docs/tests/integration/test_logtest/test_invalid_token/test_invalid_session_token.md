# Test logtest - invalid session token

## Overview

Check if `wazuh-logtest` correctly detects and handles errors when using a session token.

## Objective

- Confirm that `wazuh-logtest` detects invalid session tokens.

## General info

|Tier | Total | Time spent |
| :--:| :--:  | :--:       |
| 0   |    6 |    3s  |

## Expected behavior

- Fail if `wazuh-logtest` does not produce an error when trying to use an invalid session token.

## Code documentation

::: tests.integration.test_logtest.test_invalid_token.test_invalid_session_token
