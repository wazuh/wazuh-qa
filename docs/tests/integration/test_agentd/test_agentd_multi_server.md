# Test AgentD multi-server

## Overview

These tests will check the agent's enrollment and connection to a manager
in a multi-server environment.

## Objective

The objective is to check how the agent manages the connections to the servers depending on their status.

## General info

|Tier | Platforms | Number of tests | Time spent |
|:--:|:--:|:--:|:--:|
| 0 | Linux/Windows | 6 | 11m 27s |

## Expected behavior

Success if the agent passes the stages of each test, failure otherwise.

## Testing

The tests are based on simulating a multi-server environment with three
RemoteD simulated connections that, in each test, are in a different state.
For each situation, it is verified that the agent behaves as expected. 

### Checks

- Agent without keys:
    - **All servers will refuse the connection to remoted but will accept enrollment. 
        The agent should try to connect and enroll to each of them.**
        
    - **The first server only has enrollment available, and the third server only has remoted available. 
        The agent should enroll in the first server and connect to the third one.**
      
    - **The agent should enroll and connect to the first server, and then the first server 
        will disconnect, agent should connect to the second server with the same key.**

    - **The agent should enroll and connect to the first server, and then the first server 
        will disconnect, agent should try to enroll to the first server again,
        and then after failure, move to the second server and connect.**
      
- Agent with keys:
    - **The agent should enroll and connect to the last server.**
      
    - **The first server is available, but it disconnects, the second and third servers
        are not responding. The agent on disconnection, should try the second and
        third servers and go back finally to the first server.**
    
- **`UDP/TCP` protocols in connections.**

## Code documentation
<!-- ::: tests.integration.test_agentd.test_agentd_multi_server -->

