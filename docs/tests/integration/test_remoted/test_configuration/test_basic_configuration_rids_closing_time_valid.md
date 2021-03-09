# Test valid rids closing time values

## Overview 

Check if `wazuh-remoted` correctly start using valid `rids_closing_time` values.

## Objective

To confirm `rids_closing_time` option allows valid values.

## General info

|Tier | Number of tests | Time spent |
|:--:|:--:|:--:|
| 0 | 8 | 24 |

## Expected behavior

- Fail if remoted does not start correctly.
- Fail if API query `{protocol}://{host}:{port}/manager/configuration?section=remote` doesn't match 
  the introduced configuration on ossec.conf.

## Code documentation

::: tests.integration.test_remoted.test_configuration.test_basic_configuration_rids_closing_time_valid
