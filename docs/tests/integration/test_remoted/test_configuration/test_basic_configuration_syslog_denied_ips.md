# Test denied ip 

## Overview 

Check if `wazuh-remoted` correctly denied ip for `syslog` connection.

## Objective

TO Confirm `wazuh-remoted` denied the connection of the ip specified in `denied-ips` option.

## General info

|Tier | Number of tests | Time spent |
|:--:|:--:|:--:|
| 0 | 1 | 4 |

## Expected behavior

- Fail if remoted does not start correctly.
- Fail if remoted does not show expected warning when receive a message from a denied ip.
- Fail if API query `{protocol}://{host}:{port}/manager/configuration?section=remote` doesn't match 
  the introduced configuration on ossec.conf.

## Code documentation

::: tests.integration.test_remoted.test_configuration.test_basic_configuration_syslog_denied_ips
