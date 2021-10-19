# Test location custom sockets

## Overview 

Check if the statistics of the forwarded events to a custom socket, found in 
the `wazuh-logcollector.state` file are correct. These statistics refer to 
both `global drops`, which are referred to since `logcollector` is started, 
and `interval drops`, by default every 5 seconds.

## Objective

- To confirm that when several batches of events are successfully forwarded, 
  the `global drops` and `interval drops` values remain at zero.
- To confirm that when forwarding multiple batches of events, with the socket closed, 
  the values of the global drops and interval drops are consistent with the dropped events.

## General info

|Tier | Number of tests | Time spent |
|:--:|:--:|:--:|
| 1 | 64 | 22m45s |

## Expected behavior

- Fail if forwarding events with the socket open increases the drops registered in the statistics for this one.
- Fail if forwarding events with the socket closed the drops registered in the statistics 
  for this one are different from the real ones.

## Code documentation

::: tests.integration.test_logcollector.test_location_custom_sockets.test_location_custom_sockets