# Test active response

## Overview
These tests will check if active response command is sent correctly to the agent.

## Objective

The objective is to check that the manager correctly sent active response to the agent and that this one receives it.

## General info

|Tier | Number of tests | Time spent |
|:--:|:--:|:--:|
| 0 | 8 | 4m 16s |

## Expected behavior

- Fail if exed does not send to remoted the active response.
- Fail if remoted does not received the active response sent by execd.
- Fail if agent does not receives active response message.

## Code documentation

::: tests.integration.test_remoted.test_active_response.test_active_response
