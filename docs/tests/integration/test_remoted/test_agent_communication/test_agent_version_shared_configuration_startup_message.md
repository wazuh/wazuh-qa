# Test agent version, shared configuration and startup message
## Overview
Check if the manager receives the correct agent version, sends shared configuration and that agent sends 
startup message restart.

## Objective

To confirm that there are no problems in the following:

- The agent sends its version to the manager, and it is stored correctly in `global.db`.
- The manager pushes the shared configuration correctly to the agent, and the agent is restarted.
- After the agent restarts, it sends the startup message correctly.

## General info

|Tier | Number of tests | Time spent |
|:--:|:--:|:--:|
| 0 | 6 | 3m |

## Expected behavior

- Fail if the manager does not receive the correct agent version.
- Fail if the manager does not send correctly shared configuration to the agent.
- Fail if the agent does not restart correctly after receives shared configuration.
- Fail if the agent does not send the startup message to the manager.

## Code documentation

::: tests.integration.test_remoted.test_agent_communication.test_agent_version_shared_configuration_startup_message
