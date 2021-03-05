# Test manager ACK

## Overview

These tests will check if the manager sends the ACK message after receiving the `start-up` message from agent.

## Objective

The objective is to check that the manager sends the ACK message using the different protocols.

## General info

|Tier | Number of tests | Time spent |
|:--:|:--:|:--:|
| 0 | 4 | 1m 15s |

## Expected behavior

Success if the agent receives the ACK message from the manager after sending the `start-up` message. Failure otherwise.

## Testing

The testing is based on configuring the manager to receive messages via `TCP`, `UDP`, `TCP-UDP` and `UDP-TCP`.

First, the simulated agent will send the `start-up` message to the manager, and then, the agent will save all the
incoming messages from the agent in a buffer.

Next, the test will search the ACK message in the agent buffer (it contains the string `#!-agent ack`).

### Checks

- Manager sends the ACK message using `TCP` protocol.
- Manager sends the ACK message using `UDP` protocol.
- Manager sends the ACK message using `TCP,UDP` configuration.
- Manager sends the ACK message using `UDP,TCP` configuration.


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
::: tests.integration.test_remoted.test_manager_messages.test_manager_ack
