# Test multi agent status

## Overview

These tests will check if the agent status appears **active** after `start-up` and `keep-alive` events, sent by
several agents using different protocols.

## Objective

The objective is to check the agent's status is updated correctly after sending the `start-up` and `keep-alive`
events.

## General info

|Tier | Number of tests | Time spent |
|:--:|:--:|:--:|
| 2 | 6 | 37s |

## Expected behavior

Success if the agent status is `active`, failure otherwise.

## Testing

The testing is based on configuring the manager to receive messages via `TCP`, `UDP` and `TCP-UDP` as well
as using the default port and a custom port.

The process that is carried out is as follows:

- Create and register `n` agents in the manager.
- For each agent, send the `start-up` and `keep-alive` events in separate threads.
- Check all agents' status are **active** querying to `wazuh-db` using the `wdb` socket.

### Checks

- TCP and port 1514.
- UDP and port 1514.
- TCP,UDP and port 1514.
- TCP and port 56000.
- UDP and port 56000.
- TCP,UDP and port 56000.

## Code documentation
::: tests.integration.test_remoted.test_agent_communication.test_multi_agent_status
