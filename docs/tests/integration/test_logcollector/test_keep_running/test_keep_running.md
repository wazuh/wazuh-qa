# Test keep running

## Overview 

Check if Wazuh works correctly when monitoring log files (through `logcollector`) 
and these are modified by a log rotation.

## Objective

- To confirm that `logcollector` continues to monitor log files after they have been rotated.

## General info

|Tier | Number of tests | Time spent |
|:--:|:--:|:--:|
| 0 | 1 | 54s |

## Expected behavior

- Fail if `logcollector` cannot read data from a log after it is rotated.

## Code documentation

::: tests.integration.test_logcollector.test_keep_running.test_keep_running