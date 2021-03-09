# Test active response

## Overview
These tests will check if an active response command is sent correctly to the agent.

## Objective

The objective is to check that the manager correctly sent an active response to the agent and that this one receives it.

The following message is written in active response socket (`/var/ossec/queue/alerts/ar`):

``` 
(local_source) [] NRN 073 dummy-ar admin 1.1.1.1 1.1 44 (any-agent) any->/testing/testing.txt - -
```

- `wazuh-remoted` should read active response socket generating the following debug message:

```
2021/03/08 14:00:04 wazuh-remoted[57340] ar-forward.c:40 at AR_Forward(): DEBUG: Active response request received: 
(local_source) [] NRN 073 dummy-ar admin 1.1.1.1 1.1 44 (any-agent) any->/testing/testing.txt - -
```

- `wazuh-remoted` should send the active response command, generating the following debug message

```
2021/03/09 10:17:10 wazuh-remoted[21947] ar-forward.c:99 at AR_Forward(): DEBUG: Active response sent: 
#!-execd dummy-ar admin 1.1.1.1 1.1 44 (any-agent) any->/testing/testing.txt - -
```

- The agent should receive active response command generating the following debug message 

```
2021/03/04 14:07:44 ossec-agentd[49945] receiver.c:92 at receive_msg(): DEBUG: Received message: 
'#!-execd dummy-ar admin 1.1.1.1 1.1 44 (any-agent) any->/testing/testing.txt - -
```

## General info

|Tier | Number of tests | Time spent |
|:--:|:--:|:--:|
| 0 | 8 | 4m 16s |

## Expected behaviour

- Fail if wazuh-execd does not send to remoted the active response.
- Fail if remoted does not receive the active response sent by execd.
- Fail if the agent does not receive the active response message.

## Code documentation

::: tests.integration.test_remoted.test_active_response.test_active_response
