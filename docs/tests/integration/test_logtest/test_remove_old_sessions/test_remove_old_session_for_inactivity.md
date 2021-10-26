# Test logtest - remove old session for inactivity

## Overview

Check if `wazuh-logtest` correctly detects and handles the situation where trying
to use more sessions than allowed and then old sessions are released due to
inactivity.

## Objective

- Confirm that `wazuh-logtest` removes the inactive sessions after a certain time.

## General info

|Tier | Total | Time spent |
| :--:| :--:  | :--:       |
| 0   |    1 |    1m 5s  |

## Expected behavior

- Fail if `wazuh-logtest` does not start.
- Fail if `wazuh-logtest` can not create a new session.
- Fail if `wazuh-logtest` old session is not removed.

## Code documentation

::: tests.integration.test_logtest.test_remove_old_sessions.test_remove_old_session_for_inactivity
