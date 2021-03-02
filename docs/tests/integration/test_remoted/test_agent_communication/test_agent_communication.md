# Test agent communication
## Overview 
Check that manager-agent communication through remoted socket works as expected.

## Objective

Confirm that there are no problems when the manager tries to communicate with an agent to ask for configuration or 
state files using the remoted socket.

## General info

|Tier | Number of tests | Time spent |
|:--:|:--:|:--:|
| 0 | 1 | 3min |

**We need to find a way to reduce testing time**

## Expected behavior

- Fail if remoted doesn't return the requested data
- Fail if remoted doesn't return an error message when the agent is disconnected
- Fail if remoted couldn't connect with an active agent
## Testing

- Test getconfig request
- Test getstate request
- Test getconfig request for a disconnected agent

## Code documentation
::: tests.integration.test_remoted.test_agent_communication.test_agent_communication