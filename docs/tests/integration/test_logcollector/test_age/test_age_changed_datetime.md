# Test Age - Changed datetime
## Overview 

Ensure that when date of the system change logcollector use properly age value, ignoring files that have not been
modified for a time greater than age value using current date when system datetime changed while `wazuh-logcollector` 
is running.

## Objective

- To confirm `age` option is used correctly when system datetime change.

## General info

|Tier | Number of tests | Time spent |
|:--:|:--:|:--:|
| 0 | 40 | 2m40s |

## Expected behavior

- Fail if files that have not been modified for a time greater than age value are not ignored.
- Fail if files that have been modified for a time greater than age value are ignored.

## Code documentation

::: tests.integration.test_logcollector.test_age.test_age_datetime_changed



