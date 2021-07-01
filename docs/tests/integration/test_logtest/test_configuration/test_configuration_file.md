# Test logtest - configuration file

## Overview

Check if `wazuh-logtest` works as expected under different pre-defined
configurations that either produce `wazuh-logtest` to correctly start; to be
disabled or to log an error.

## Objective

- Confirm that, under different sets of configurations, `wazuh-logtest`
correctly handles the configuration and creates a log entry on the Wazuh log,
reporting the result of loading it.

## General info

|Tier | Total | Time spent |
| :--:| :--:  | :--:       |
| 0   |    5 |    1m30s  |

## Expected behavior

- Fail if the expected log entry is not found among the Wazuh logs.

## Code documentation

::: tests.integration.test_logtest.test_configuration.test_configuration_file
