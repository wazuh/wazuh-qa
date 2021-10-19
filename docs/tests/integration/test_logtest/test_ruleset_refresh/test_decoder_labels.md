# Test logtest - decoder labels
## Overview

Checks if modifying the configuration of the decoder, by using its labels, takes
effect when opening new logtest sessions without having to reset the manager.

## Objective

- To confirm that, when adding a new file in the default decoders directory, the
new decoders are correctly loaded when a new session of logtest is opened
- To confirm that, when adding a new custom decoder directory, the new decoders
are correctly loaded when a new session of logtest is opened
- To confirm that, when adding a new decoder file, the
new decoders are correctly loaded when a new session of logtest is opened
- To confirm that, when excluding a decoder file, the
decoders are not loaded when a new session of logtest is opened

## General info

|Tier | Total | Time spent |
| :--:| :--:  | :--:       |
| 0   |    4 |    3s  |


## Expected behavior

- Fail if `wazuh-analysisd` is not running
- Fail if `wazuh-analysisd` returns an error
- Fail if `wazuh-analysisd` does not match the corresponding decoder
- Fail if `wazuh-analysisd` does match the decoder when it should not (exclude)

## Code documentation

::: tests.integration.test_logtest.test_ruleset_refresh.test_decoder_labels
