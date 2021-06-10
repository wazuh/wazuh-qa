# Test options - State interval
## Overview 

Check if `wazuh-logcollector` update `wazuh-logcollector.state` file properly when a monitored file is removed.

## Objective

- To confirm the `wazuh-logcollector.state` file is updated when a monitored file is removed.
- To confirm the `logcollector.open_attempts` option is correctly set, and it works correctly.
- To confirm the `logcollector.state_interval` option is correctly set, and it works correctly.

## General info

|Tier | Number of tests | Time spent |
|:--:|:--:|:--:|
| 1 | 3 | 50.61s |

## Expected behavior

- Pass if `wazuh-logcollector` update `wazuh-logcollector.state` file, removing deleted file.
- Pass if `wazuh-logcollector` try to open the removed filed. The number of attempts should be equal 
  to `logcollector.open_attempts` option is correctly set, and it works correctly.
- Pass if `wazuh-logcollector` update `wazuh-logcollector.state` using `logcollector.state_interval` value 

## Code documentation

::: tests.integration.test_logcollector.test_options.test_options_state_interval_no_file
