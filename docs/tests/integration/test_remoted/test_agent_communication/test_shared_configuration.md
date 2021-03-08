# Test shared configuration push
## Overview
Check if the manager pushes shared configuration to agents as expected.

## Objective

Confirm that there are no problems when the manager is supposed to push shared configuration to agents.

By default, agents send a keep alive message to the manager every 10 seconds. For each one of these messages,
the Manager needs to check if the configuration for agent's groups have changed. If so, then the Wazuh Manager 
needs to push the new effective configuration (`merge.mg` file) for the agent. One `merge.mg` must be pushed only once.

If the agent is added to a new group, a new `merge.mg` file must be generated for this agent and the configuration
must be pushed as well.

## General info

To avoid race conditions problems, the keep_alive module module on agent_simulator is disabled and the keep_alive 
messages are sent manually. This way we avoid the scenario where keep_alive thread sends two messages with the same
deprecated checksum while the process_message thread updates such checksum. This would cause an error because the
manager would send to the agent the shared configuration twice and it shouldn't.

|Tier | Number of tests | Time spent |
|:--:|:--:|:--:|
| 0 | 3 | 3m |

## Expected behavior
- Fail if remoted doesn't send the up file command.
- Fail if remoted doesn't push the shared configuration when required.
  Fail if remoted doesn't send the close file command.
  Fail if remoted push the same shared configuration twice.
  Fail if remoted doesn't push a new shared configuration after adding the agent to a new group.
- Fail if remoted doesn't return an error message when the agent is disconnected.
- Fail if remoted couldn't connect with an active agent.
## Testing
- Test getconfig request
- Test getstate request
- Test getconfig request for a disconnected agent

## Code documentation
::: tests.integration.test_remoted.test_agent_communication.test_request_agent_info
