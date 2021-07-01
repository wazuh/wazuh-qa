# Test logtest - get configuration socket

## Overview

Check if `wazuh-analisysd` correctly retrieves the `rule_test` configuration.

## Objective

- Confirm that, under different sets of configurations, `wazuh-analisysd`
returns the right information from the `rule_test` configuration block.

## General info

|Tier | Total | Time spent |
| :--:| :--:  | :--:       |
| 0   |    5 |    1m23s  |

## Expected behavior

- Fail if `wazuh-analisysd` does not retrieve the information in the expected format.
- Fail if `wazuh-analisysd` does not retrieve the expected value of the `enabled` field.
- Fail if `wazuh-analisysd` does not retrieve the expected value of the `threads` field.
- Fail if `wazuh-analisysd` does not retrieve the expected value of the `max_sessions` field.
- Fail if `wazuh-analisysd` does not retrieve the expected value of the `session_timeout` field.

## Code documentation

::: tests.integration.test_logtest.test_configuration.test_get_configuration_sock
