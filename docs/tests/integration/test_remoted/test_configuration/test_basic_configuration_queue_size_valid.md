# Test valid queue size

## Overview 

Check if `wazuh-remoted` correctly start using valid `queue_size` values.

## Objective

To confirm that `queue_size` option allow correct values.

## General info

|Tier | Number of tests | Time spent |
|:--:|:--:|:--:|
| 0 | 3 | 9 |

## Expected behavior

- Fail if remoted does not start correctly.
- Fail if API query `{protocol}://{host}:{port}/manager/configuration?section=remote` doesn't 
  match the introduced configuration on ossec.conf.

## Code documentation

::: tests.integration.test_remoted.test_configuration.test_basic_configuration_queue_size_valid
