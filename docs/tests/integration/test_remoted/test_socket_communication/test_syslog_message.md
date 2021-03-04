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
| 0 | 40 | 4 m 11 s |

## Expected behavior

- Fail if `wazuh-remoted` doesn't start with a valid configuration.
- Fail if `wazuh-remoted` doesn't receive the syslog message.
- Skip the check for multi-logs and UDP. The Syslog protocol for UDP only allows one message per datagram 
  and for TCP, you can send as many as you want if all of them are separated by `\n`.

## Testing

### Checks

The test will send the following messages to `wazuh-remoted` syslog server:
- Dummy value: `Syslog message sent by wazuh-qa to test remoted syslog`.
- Failed login SSHD: 
  `Feb  4 16:39:29 ip-10-142-167-43 sshd[6787]: Invalid user single-log-w-header from 127.0.0.1 port 41328`.
- Failed login SSHD with a [PRI header](https://tools.ietf.org/html/rfc3164#section-4.1.1): 
  `<1>Feb  4 16:39:29 ip-10-142-167-43 sshd[6787]: Invalid user single-log-w-header from 127.0.0.1 port 41328`.
- Multiple logs at once: the failed login sshd attempt and a logon success.
- Multiple logs at once with [PRI headers](https://tools.ietf.org/html/rfc3164#section-4.1.1): 
  the failed login sshd attempt and a logon success.
- Combination of all the messages from above. 
- Messages with a bad formatted PRI header.
  
These logs will generate events that will appear in the `archives.log` file with this format:
```
2021 Feb 24 10:30:10 centos-8->127.0.0.1 Syslog message sent by wazuh-qa to test remoted syslog
```
With all of this, the test will apply a custom configuration for `wazuh-remoted`, send the message and search the event 
in the `archives.log`. 

The configuration applied to the test is this one:

- **UDP and port 514**.
- **UDP and port 51000**.
- **TCP and port 514**.
- **TCP and port 51000**.
- **udp and port 514**.
- **udp and port 51000**.
- **tcp and port 514**.
- **tcp and port 51000**.

## Code documentation
::: tests.integration.test_remoted.test_socket_communication.test_syslog_message