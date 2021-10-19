# Test agentd

## Overview 

`wazuh-agentd` is the client-side daemon that communicates with the manager.
`agent-auth` is the client application used along with `wazuh-authd` 
to automatically add agents to a Wazuh manager.

These tests check if the `agentd` daemon correctly manages the enrollment (along with `agent-auth`) and connections,
both in a multi-server environment and in a single-server environment.

## Objective

Confirm that the `agentd` daemon is handling the enrollment and connection of the agent to the manager correctly.

## General info

|Tier | Number of tests | Time spent |
|:--:|:--:|:--:|
| 0 | 93 | 59m 49s |

## List of agentd tests

- **[Test agent-auth enrollment](test_agent_auth_enrollment.md)**: Check different situations that can
  occur on the `agent-auth` program during agent enrollment.

- **[Test agentd enrollment params](test_agentd_enrollment_params.md)**: Check different situations that can
  occur on the `wazuh-agentd` daemon during agent enrollment.

- **[Test agentd multi-server](test_agentd_multi_server.md)**: Check that the agent can enroll under different
  test conditions in a multi-server environment.

- **[Test agentd parametrized reconnections](test_agentd_parametrized_reconnections.md)**: Check how the agent
  behaves when there are delays between connection attempts to the server.

- **[Test agentd reconnections](test_agentd_reconnection.md)**: Check how the agent behaves when it loses connection 
  with the server under different test conditions.