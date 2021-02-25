# Test syslog messages
## Overview
These tests will check if `wazuh-remoted` can receive messages to its syslog server. This message will be received in the port configured in the `remote` section, using the `syslog` connection. The `syslog` functionality accepts these protocols `UDP` and `TCP` connections, but not at the same time.

For `syslog`, you can send messages to the socket using any protocol without needing to add any header to the message but, any message must end with a `\n`. Otherwise, the event will remain in the socket until a message with the EOL character arrives.

Finally, `wazuh-remoted` doesn't log anywhere the events received in its syslog server unless the `logall` option is set to `yes`. If it is enabled, `wazuh-remoted` will log in `/var/ossec/logs/archives/archives.log` any syslog event using this format:
```buildoutcfg
Year Month Day HH:MM:SS hostname->address syslog message
```

For example:
```buildoutcfg
2021 Feb 24 10:30:10 centos-8->127.0.0.1 Syslog message sent by wazuh-qa to test remoted syslog with UDP at 514
```

## Objective

Confirm `wazuh-remoted` can receive messages to its syslog server. This confirmation is done by searching the syslog messages in the `archives.log`. 

## General info

|Tier | Number of tests | Time spent |
|:--:|:--:|:--:|
| 0 | 4 | 95s |

## Expected behavior

- Fail if `wazuh-remoted` doesn't start with a valid configuration.
- Fail if `wazuh-remoted` doesn't receive the syslog message.

## Testing
Checks executed in this test
### Checks
- **UDP and port 514**: `wazuh-remoted` must log a line similar to this: `2021 Feb 24 10:30:10 centos-8->127.0.0.1 Syslog message sent by wazuh-qa to test remoted syslog with UDP at 514`.
- **UDP and port 51000**: `wazuh-remoted` must log a line similar to this: `2021 Feb 24 10:30:10 centos-8->127.0.0.1 Syslog message sent by wazuh-qa to test remoted syslog with UDP at 51000`. 
- **TCP and port 514**: `wazuh-remoted` must log a line similar to this: `2021 Feb 24 10:30:10 centos-8->127.0.0.1 Syslog message sent by wazuh-qa to test remoted syslog with TCP at 514`.
- **TCP and port 51000**: `wazuh-remoted` must log a line similar to this: `2021 Feb 24 10:30:10 centos-8->127.0.0.1 Syslog message sent by wazuh-qa to test remoted syslog with TCP at 51000`.

## Code documentation
::: tests.integration.test_remoted.test_socket_communication.test_syslog_message