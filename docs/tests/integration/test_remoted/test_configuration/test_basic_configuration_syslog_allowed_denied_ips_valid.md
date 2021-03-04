# Test allowed and denied ips for valid values

## Overview 

Check if `wazuh-remoted` correctly start using valid ip addresses for `allowed-ips` and `denied-ips` labels.

## Objective

To confirm that `wazuh-remote` accepts valid ip addresses for `allowed-ips` and `denied-ips` labels.

## General info

|Tier | Number of tests | Time spent |
|:--:|:--:|:--:|
| 0 | 5 | 12 |

## Expected behavior

- Fail if remoted does not start correctly.
- Fail if API query `{protocol}://{host}:{port}/manager/configuration?section=remote` doesn't 
  match the introduced configuration on ossec.conf.

## Code documentation

::: tests.integration.test_remoted.test_configuration.test_basic_configuration_syslog_allowed_denied_ips_valid
