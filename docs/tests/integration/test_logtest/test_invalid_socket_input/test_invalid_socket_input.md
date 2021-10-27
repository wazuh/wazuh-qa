# Test logtest - invalid socket input

## Overview

Check if `wazuh-logtest` correctly detects and handles errors when sending a
message through the socket to `analysisd`.

## Objective

- Confirm that the comunication through the sockets works well by verifying that
all the test cases produce the right output.

## General info

|Tier | Total | Time spent |
| :--:| :--:  | :--:       |
| 0   |    26 |    1s  |

## Expected behavior

- Fail if the message received through the socket does not match the expected output.

## Code documentation

::: tests.integration.test_logtest.test_invalid_socket_input.test_invalid_socket_input
