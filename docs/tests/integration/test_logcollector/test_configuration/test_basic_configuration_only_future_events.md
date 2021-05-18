# Test basic configuration - Only future events
## Overview 

Check if `wazuh-agent` fails using invalid `only-future-events` values and allows valid `only-future-events` 
values. It also tests the attribute `max-size` for the option which is supposed to accept a number and an unit suach 
as 'KB' or 'GB' 

## Objective

- To confirm `only-future-events` option and the attribute `max-size`allow valid values.
- To confirm `wazuh-logcollector` and `wazuh-agent` fails when invalid `only-future-events`  or invalid `max-size` 
  values are provided
- To confirm the API response is equal to set configuration.

## General info

|Tier | Number of tests | Time spent |
|:--:|:--:|:--:|
| 0 | 11 | 53.3s |

## Expected behavior

- Fail if `wazuh-logcollector` or `wazuh-agent` start correctly when invalid 
  `only-future-events` values are provided.
- Fail if `wazuh-logcollector` or `wazuh-agent` does not start correctly when invalid 
  `only-future-events` values are provided.
- Fail if the API response is different from the Wazuh configuration.

## Code documentation 

::: tests.integration.test_logcollector.test_configuration.test_basic_configuration_only_future_events
