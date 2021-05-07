# Test Age - Basic
## Overview 

Check that those files that have not been modified for a time greater than age value, are ignored for logcollector. 
Otherwise, files should not be ignored. Also, it checks logcollector detect modification time changes in 
monitored files and catch new logs from ignored and not ignored files.

## Objective

- To confirm `age` option is used correctly when system datetime does not change.

## General info

|Tier | Number of tests | Time spent |
|:--:|:--:|:--:|
| 0 | 5 | 1m50s |

## Expected behavior

- Fail if files that have not been modified for a time greater than age value are not ignored.
- Fail if files that have been modified for a time greater than age value are ignored.

## Code documentation

::: tests.integration.test_logcollector.test_age.test_age_basic



