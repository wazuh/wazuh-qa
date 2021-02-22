# Overview

These tests will check if `wazuh-remoted` sends the message `#pong` through the socket after receiving the `#ping` message.

This message will be received in the port configured in the `remote` section, using the `secure` connection. Also, depending on the protocol used, these messages may vary:

- **udp**: the manager must receive the plain message `#ping` without headers and respond `#pong`, also without the headers.
  
- **tcp**: for this protocol, the manager must receive the `#ping` message with a header. This header is the message size transformed to an `uint32` in binary (0x00000005) in little-endian. The answer must contain the header with the message size too.   

## Objective

Confirm `wazuh-remoted` keeps sending the `#pong` message for different ports and protocols.

## General info

|Tier | Number of tests | Time spent |
|:--:|:--:|:--:|
| 0 | 4 | 8s |

## Expected behavior

- Fail if `wazuh-remoted` doesn't start with a valid configuration.

- Fail if `wazuh-remoted` doesn't respond with the `#pong` message. 

## Testing
Checks executed in this test
### Checks
- **UDP and port 1514**: `wazuh-remoted` must response `b'#pong'`.
- **UDP and port 56000**: `wazuh-remoted` must response `b'#pong'`. 
- **TCP and port 1514**: `wazuh-remoted` must response `b'\x05\x00\x00\x00#pong'`
- **TCP and port 56000**: `wazuh-remoted` must response `b'\x05\x00\x00\x00#pong'`

## Code documentation
::: tests.integration.test_remoted.test_socket_communication.test_ping_pong_message