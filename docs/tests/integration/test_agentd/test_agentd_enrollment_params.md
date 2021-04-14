# Test AgentD enrollment params

## Overview

These tests will verify different situations that may occur at AgentD during enrollment.

## Objective

The objective is to check the enrollment of the agent using certain settings
in the `ossec.conf` file produces the expected responses from the server.

## General info

|Tier | Platforms | Number of tests | Time spent |
|:--:|:--:|:--:|:--:|
| 0 | Linux/Windows | 34 | 10m 25s |

## Expected behavior

Success, if the responses received are consistent with the parameters sent, failure otherwise.

## Testing

The tests are based on using specific configurations for the agent, initiate the agent enrollment
with the manager, and finally, verify that the response received matches the expected one.
Both configurations and responses are found in a YAML file.

### Checks

- **Test cases found in the file: `wazuh_enrollment_tests.yaml`**


## Code documentation
<!-- ::: tests.integration.test_agentd.test_agentd_enrollment_params -->