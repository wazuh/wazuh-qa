# Test remote enrollment option for authd
## Overview

Check if `wazuh-authd` disables 1515 ssl connections when `remote_enrollment` option is set to `no`,
and it accepts enrollments when the option is set to `yes`.

It checks that the socket is or is not created according to the configuration and that the following [1] logs appear in `ossec.log`:
- Port 1515 was set as disabled
- Accepting connections on port 1515.

It is executed for stand alone manager and also for cluster manager and worker[2].

## Objective

- To confirm `remote_enrollment` option works as expected

## General info

|Tier | Number of tests | Time spent |
|:--:|:--:|:--:|
| 0 | 5 | 12.94s |

## Expected behavior

- Fail if `remote_enrollment` is set to `yes` but the remote registration does not work.
- Fail if `remote_enrollment` is set to `no` but the remote registration continues enabled.
- Fail if the expected logs [1] doesn't appear in ossec.log file

## Notes

[2] For the worker case, as there is no master to report, the expected response from the worker is 'ERROR: Cannot comunicate with master'. THis confirms that the worker has attempted to communicate with the master to registrate the agent but it was not possible because the master is offline. The purpose of this test is not to check if the cluster works as expected so this would be enough to check that the option works right and remote enrollment is correctly enabled or disabled.

## Code documentation


::: tests.integration.test_authd.test_remote_enrollment -->