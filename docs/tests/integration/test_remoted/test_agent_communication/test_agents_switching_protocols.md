# Test the connectivity after switching the protocols in the agents

## Overview

These tests will check if the agents connected to a manager configured with both protocols can change their protocol, 
restart and reconnect without issues to the manager.

## Objective

By using the `tcp,udp` option for `protocol` in the remote settings, the connection to the manager must be completely 
transparent to the agents. Agents using different protocols must be able to connect to the manager without issues and
appear in the `global.db` as active.

All of this means the agents can switch from one protocol to another and reconnect to the manager without restarting it
and without errors and keep appearing as active agents.

The objective of these tests is to ensure the agents will be able to reconnect without issues in an infrastructure where
the agents may change its protocols on the fly.


## General info

|Tier | Number of tests | Time spent |
|:--:|:--:|:--:|
| 0 | 2 | 80 s |

## Expected behavior

The agents must reconnect without issues and appear as `active` in the `global.db`.

## Testing

The test consists of connecting two agents to a manager configured with `UDP,TCP`. One agent will connect using `TCP` 
and the other one will use `UDP`. Then, the test will wait until they appear as active in the DB.

The next step is to stop all the agents and wait until they appear as `disconnected` . The time for this change in the 
DB can be specified in the configuration file using the option `agents_disconnection_time`. For these tests, it is set 
to 5 seconds to speed up the tests.

Once the agents appear as disconnected, the test will change the protocols for the agents and restart them. Then, they 
must appear as `active` again in the `db`. 

### Checks

- Two agents must reconnect to the port `1514`.
- Two agents must reconnect to the port `56000`.

## Code documentation
::: tests.integration.test_remoted.test_agent_communication.test_agents_switching_protocols
