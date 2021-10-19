# Test queue size too big

## Overview 

Check if `wazuh-remoted` correctly shows warning message using a too big `queue_size` value.

## Objective

To confirm that `wazuh-remoted` shows expected warning if a `queue_size` value is greater than 262144.

## General info

|Tier | Number of tests | Time spent |
|:--:|:--:|:--:|
| 0 | 1 | 3 |

## Expected behavior

- Fail if remoted does not start correctly.
- Fail if API query `{protocol}://{host}:{port}/manager/configuration?section=remote` doesn't 
  match the introduced configuration on ossec.conf.

## Code documentation

::: tests.integration.test_remoted.test_configuration.test_basic_configuration_queue_size_too_big
