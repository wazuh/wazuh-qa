# Test MITRE check alert

## Overview 

Check if `wazuh-analysisd` generates alerts enriching its fields with MITRE information.   

## Objective

The objective consists on checking if `wazuh-analysisd` can generate alerts using custom rules 
that contains the `mitre` field to enrich those alerts with MITREs IDs, techniques and tactics.

This test will check if the alert is syntactically and semantically correct. Otherwise, the 
test will raise an exception.  

## General info

|Tier | Number of tests | Time spent |
|:--:|:--:|:--:|
| 0 | 15 | 42.4s |

## Expected behavior

- Fail if `wazuh-analysisd` doesn't generate the expected alert.
- Fail if `wazuh-analysisd` generates an alert with syntactic or semantic errors.
- Fail if `wazuh-analysisd` generates a correctly formatted alert for those 
  cases with invalid configurations.

## Code documentation

::: tests.integration.test_analysisd.test_mitre.test_mitre_check_alert