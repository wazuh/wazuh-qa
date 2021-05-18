# Test only future events

## Overview 

Check if Wazuh works correctly when monitoring log files (through `logcollector`), 
and for whatever reason, it becomes unavailable for some time. When Wazuh is active 
again these logs that could not be monitored can be analyzed using the `only-future-events` option.

## Objective

- To confirm that `logcollector` continues to monitor log files after they have been rotated.

## General info

|Tier | Number of tests | Time spent |
|:--:|:--:|:--:|
| 0 | 1 | 30s |

## Expected behavior

- Fail if `logcollector` cannot read data from a log after it is rotated.

## Code documentation

::: tests.integration.test_logcollector.test_only_future_events.test_only_future_events