# Test protocols communication

## Overview

These tests will check if there is a correct communication between the manager and the agent after establishing `TCP`,
`UDP` or both as receiving and sending protocols.

## Objective

The objective is to check that the manager correctly receives information from the agent via TCP, UDP and both
protocols simultaneously.

## General info

|Tier | Number of tests | Time spent |
|:--:|:--:|:--:|
| 0 | 8 | 2m 23s |

## Expected behavior

Success if the event has been found in the manager's `queue` socket after sending it from the agent, using different
protocols and ports. Failure otherwise.

## Testing

The testing is based on configuring the manager to receive messages via `TCP`, `UDP`, `TCP-UDP` and `UDP-TCP` as well
as using the default port and a custom port.

After this, two jobs are launched:

- A monitoring job that is based on monitoring the manager's  `queue` socket to see the events received.

- A job that creates, registers an agent and sends a defined message to the manager.

These jobs are launched in separate threads, launching first the monitoring and then the sending of the message with
a difference of 2 seconds.

### Checks

- **TCP and port 1514**
- **UDP and port 1514**
- **TCP,UDP and port 1514**
- **UDP,TCP and port 1514**
- **TCP and port 56000**
- **UDP and port 56000**
- **TCP,UDP and port 56000**
- **UDP,TCP and port 56000**

## Comments

An important aspect to take into account is the time needed by wazuh-remoted to reload the `client.keys`.
By default it is **10 seconds**, but this option is configurable in the `internal_options.conf`, using the
following directive:

```
remoted.keyupdate_interval=2
```

The test itself waits until the info is loaded, so reducing this time will also reduce the test time.
It is recommended to set this time between 2 and 5 seconds.

## Code documentation
::: tests.integration.test_remoted.test_agent_communication.test_protocols_communication
