# Test agent requests for information
## Overview
Check that manager-agent communication through remoted socket works as expected.

## Objective

Confirm that there are no problems when the manager tries to communicate with an agent to ask for configuration or
state files using the remoted socket.

As the test has nothing to do with shared configuration files, we removed those rootcheck txt files from default agent 
group to reduce the time required by the test to make the checks.

## General info

|Tier | Number of tests | Time spent |
|:--:|:--:|:--:|
| 0 | 3 | 71.23s |

## Expected behavior

- Fail if remoted doesn't return the requested data
- Fail if remoted doesn't return an error message when the agent is disconnected
- Fail if remoted couldn't connect with an active agent
## Testing

- Test getconfig request
- Test getstate request
- Test getconfig request for a disconnected agent

## Code documentation
::: tests.integration.test_remoted.test_agent_communication.test_request_agent_info
