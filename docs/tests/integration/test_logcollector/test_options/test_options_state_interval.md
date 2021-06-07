# Test options - State interval
## Overview 

Check if logcollector works properly with different `logcollector.state_interval` values.

## Objective

- To confirm the `logcollector.state_interval` options is correctly set, and it works correctly.

## General info

|Tier | Number of tests | Time spent |
|:--:|:--:|:--:|
| 1 | 7 | 376.64s |

## Expected behavior

- Pass if logcollector shows an error log when `logcollector.state_iterval` value is invalid.
- Pass if logcollector updates the `/var/ossec/var/run/logcollector.state` file every interval specified in `logcollector.state_interval`

## Code documentation

::: tests.integration.test_logcollector.test_options.test_options_state_interval
