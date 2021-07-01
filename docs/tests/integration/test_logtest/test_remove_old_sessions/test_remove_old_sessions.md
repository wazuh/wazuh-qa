# Test logtest - remove old sessions

## Overview

Check if `wazuh-logtest` correctly detects and handles the situation when trying
to use more sessions than allowed and so, to make room, the oldest session is
released.

## Objective

- Confirm that `wazuh-logtest` releases the oldest session when a new session is
opened and the number of active sessions reached its limit.

## General info

|Tier | Total | Time spent |
| :--:| :--:  | :--:       |
| 0   |    1 |    1m  |

## Expected behavior

- Fail if `wazuh-logtest` does not start.
- Fail if `wazuh-logtest` can not create a new session.
- Fail if `wazuh-logtest` oldest session is not removed.

## Code documentation

::: tests.integration.test_logtest.test_remove_old_sessions.test_remove_old_sessions
