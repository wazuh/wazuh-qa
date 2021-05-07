# Test reconnect time

## Overview 

Check if Wazuh Windows agent reconnect to Windows event log channels using the specified `reconnect_time` 
option. These tests will disable Windows event log service and check that expected warning debugs are generated.
Then, system time is changed using `reconnect_time` value. After that, Wazuh should generate reconnect time debug log.

## Objective

- To confirm `reconnect_time` option works correctly.
- To confirm that Wazuh detect when Windows event log service is up.
- To confirm that Wazuh detect when Windows event log service is down.
- To confirm that Wazuh can reconnect to Windows event log service. 

## General info

|Tier | Number of tests | Time spent |
|:--:|:--:|:--:|
| 0 | 9 | 1m4s |

## Expected behavior

- Fail if Wazuh agent does not reconnect to Windows event log at the time specified by `reconnect_time `
- Fail if Wazuh agent does not generate a debug message when Windows event log is down

## Code documentation

::: tests.integration.test_logcollector.test_reconnect_time.test_reconnect_time