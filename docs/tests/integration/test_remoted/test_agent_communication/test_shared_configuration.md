# Test shared configuration push
## Overview
Check that manager push shared configuration to agents as expected.

## Objective

Confirm that there are no problems when the manager is supposed to push shared configuration to agents.

Agents send to the manager a keep alive every 10 seconds (by default). For each one of these messages, the Manager needs
to check if the configuration for agent's groups have changed. If so, then the Wazuh Manager needs to push the new
effective configuration (`merge.mg` file) for the agent. One `merge.mg` must be pushed only once.

If the agent is added to a new group, a new `merge.mg` file must be generated for this agent and the configuration
must be pushed as well.

## General info

|Tier | Number of tests | Time spent |
|:--:|:--:|:--:|
| 0 | 3 | 3m |

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
