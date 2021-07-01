# Test logtest - load rules decoders

## Overview

Check if `wazuh-logtest` produce the correct rule/decoder matching.

## Objective

- Confirm that `wazuh-logtest` does produce the right decoder/rule matching when
processing a log under different sets of configurations.

## General info

|Tier | Total | Time spent |
| :--:| :--:  | :--:       |
| 0   |    6 |    7s  |

## Expected behavior

- Fail if `wazuh-logtest` does not produce the expected output when processing a log.

## Code documentation

::: tests.integration.test_logtest.test_rules_decoders_load.test_load_rules_decoders
