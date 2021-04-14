# Test AgentD parametrized reconnection

## Overview

These tests will check that the connection is finally made when
there are delays between connection attempts to the server.

## Objective

The objective is to check how AgentD behaves when there are delays between connection attempts
to RemoteD using `TCP` and `UDP` protocols.

## General info

|Tier | Platforms | Number of tests | Time spent |
|:--:|:--:|:--:|:--:|
| 0 | Linux/Windows | 9 | 18m 39s |

## Expected behavior

Success if the agent connects with the manager, failure otherwise.

## Testing

The tests are based on testing a different number of connection attempts and time between
them and then, verifying that the connection between AgentD and RemoteD is finally successful. 

### Checks
  
- **Different values of `max_retries` parameter.**
- **Different values of `retry_interval` parameter.**
- **`UDP/TCP` connection.**
- **Enrollment between retries.**

## Code documentation
<!-- ::: tests.integration.test_agentd.test_agentd_parametrized_reconnections -->
