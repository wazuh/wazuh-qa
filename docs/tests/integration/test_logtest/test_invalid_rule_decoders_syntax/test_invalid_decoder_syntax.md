# Test logtest - invalid decoder syntax

## Overview

Check if `wazuh-logtest` correctly detects and handles errors when processing a decoders file.

## Objective

- Confirm that `wazuh-logtest` retrieves errors when the loaded decoders are invalid.

## General info

|Tier | Total | Time spent |
| :--:| :--:  | :--:       |
| 0   |    11 |    1s  |

## Expected behavior

- Fail if `wazuh-logtest` does not retrieve an error when it should.

## Code documentation

::: tests.integration.test_logtest.test_invalid_rule_decoders_syntax.test_invalid_decoder_syntax
