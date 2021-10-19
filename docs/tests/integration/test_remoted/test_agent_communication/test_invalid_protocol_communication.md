# Test invalid protocol communication

## Overview

These tests will check if the manager is able to receive or process an event sent from an illegal protocol
(For example, send from TCP when the manager only listens to UDP).

## Objective

Check if the manager receives messages from a protocol that is not allowed.

## General info

|Tier | Number of tests | Time spent |
|:--:|:--:|:--:|
| 0 | 4 | 1m 5s |

## Expected behavior

The manager does not receive events from non-allowed protocols.

## Testing

The testing is based on configuring the manager to receive messages via `TCP`, `UDP` and send events from the
opposite protocol.

- If we send via `TCP` and the manager listens via `UDP`, then a `ConnectionRefusedError` is expected.

- If we send over `UDP` and the manager listens on `TCP`, then a `TimeoutError` is expected because the event does
not reach the manager.

### Checks

- TCP and port 1514.
- UDP and port 1514.
- TCP and port 56000.
- UDP and port 56000.


## Code documentation
::: tests.integration.test_remoted.test_agent_communication.test_invalid_protocol_communication
