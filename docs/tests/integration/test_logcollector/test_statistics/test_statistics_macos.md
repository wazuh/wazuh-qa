# Test statistics - macOS

## Overview 

Check if Wazuh is working properly when monitoring log files (via `logcollector`), 
and saves the corresponding information in the `wazuh-logcollector.state` file.

## Objective

- To confirm that `logcollector` saves the statistics of the files it is monitoring.

## General info

|Tier | Number of tests | Time spent |
|:--:|:--:|:--:|
| 0 | 1 | 6s |

## Expected behavior

- Pass if macOS statistics on a Darwin system are found with the `<log_format>macos</log_format>` in the `localfile` block.

## Code documentation

::: tests.integration.test_logcollector.test_statistics.test_statistics_macos