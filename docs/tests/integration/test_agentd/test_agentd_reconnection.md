# Test AgentD reconnection

## Overview

These tests will check that, during enrollment, the agent re-establishes communication with the manager
under different situations that interrupt it.

## Objective

The objective is to check that, with different states in the clients.key file, the agent
successfully enrolls after losing connection with remoted.

## General info

|Tier | Platforms | Number of tests | Time spent |
|:--:|:--:|:--:|:--:|
| 0 | Linux/Windows | 10 | 17m 53s |

## Expected behavior

Success if the agent enrolls and starts communication with remoted, failure otherwise.

## Testing

The tests are based on verifying that AgentD is communicating with RemoteD (if the agent is already enrolled),
configuring RemoteD to reject this connection, and finally verifying that the agent is enrolled again.

The above is done under the following states of the agent's `client.keys` file:
- It contains valid keys.
- It is empty.
- It does not exist.

### Checks

- **The agent has keys and loses communication with RemoteD.**
- **The agent does not have keys and loses communication with RemoteD when enrollment has been started.**
- **The agent does not have `client.keys` file and loses communication with RemoteD when enrollment has been started.**
- **The agent has keys, loses communication with RemoteD, and performs multiple enrollment requests.**
- **The agent does not have keys, RemoteD is unavailable for several seconds and multiple connection requests 
    are performed before a new enrollment is made.**

## Code documentation
<!-- ::: tests.integration.test_agentd.test_agentd_reconnection -->
