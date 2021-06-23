# Test agent pending status

## Overview

These tests will check if the agent status appears **disconnected** after just sending the `start-up` event, sent by
several agents using different protocols.

## Objective

The objective is to check the agent's status is updated correctly after only send the `start-up` event.

## General info

|Tier | Number of tests | Time spent |
|:--:|:--:|:--:|
| 0 | 6 | 327s |

## Expected behavior

Success if the agent status is `disconnected`, failure otherwise.

## Testing

The testing is based on configuring the manager to receive messages via `TCP`, `UDP` and `TCP-UDP` as well
as using the default port and a custom port.

The process that is carried out is as follows:

- Create and register `n` agents in the manager.
- The agent, sends the `start-up`.
- Check the agent status is **disconnected** querying to `wazuh-db` using the `wdb` socket.

### Checks

- TCP and port 1514.
- UDP and port 1514.
- TCP,UDP and port 1514.
- TCP and port 56000.
- UDP and port 56000.
- TCP,UDP and port 56000.

## Code documentation
::: tests.integration.test_remoted.test_agent_communication.test_agent_pending_status