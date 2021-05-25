# Test basic configuration - Age
## Overview

Check if `wazuh-authd` actually disables 1515 ssl connections when `remote_enrollment` option is set to `no`,
and it accepts enrollments when the option is set to `yes`.

It checks that the socket is or is not created according to the configuration and that the following [1] logs appear in `ossec.log`:
- Port 1515 was set as disabled
- Accepting connections on port 1515.

It is executed for stand alone manager and also for cluster manager and worker[2]

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

[2] Currently we've disabled the case where manager is a cluster node and remote enrollment is enabled because, as there is 
no master node to connect with, the worker raises the following error: 'ERROR: Cannot communicate with master'. We could 
add a simulated master node for the test but it would be too much work for what little testing it would provide so 
we won't do it for the time being

## Code documentation


::: tests.integration.test_authd.test_remote_enrollment -->