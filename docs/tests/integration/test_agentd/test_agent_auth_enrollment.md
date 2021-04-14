# Test agent-auth enrollment

## Overview

These tests will verify different situations that may occur at agent-auth program during enrollment.

## Objective

The objective is to check that the parameters sent by the agent-auth program to the AuthD daemon
are consistent with its responses.

## General info

|Tier | Platforms | Number of tests | Time spent |
|:--:|:--:|:--:|:--:|
| 0 | Linux/Windows | 34 | 1m 25s |

## Expected behavior

Success, if the responses received are consistent with the parameters sent, failure otherwise.

## Testing

The tests are based on using certain parameters to enroll the agent with the manager.
The enrollment is then started, and the response received is compared with
the expected one. Both parameters and responses are found in a YAML file.

### Checks

- **Test cases found in the file: `wazuh_enrollment_tests.yaml`**

## Code documentation
<!-- ::: tests.integration.test_agentd.test_agent_auth_enrollment -->