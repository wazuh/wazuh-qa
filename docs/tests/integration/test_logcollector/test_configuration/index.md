# Test basic configuration

## Overview 

These tests check if the introduced configuration works as expected for valid values and if the API 
response for configuration requests coincides with the one introduced in the configuration file.

For invalid ones, it checks if `wazuh-logcollector` for manager and `wazuh-agent` for agent returns 
the expected error message.

## Objective

Confirm that the different options for logcollector configuration work and are correctly loaded.

## General info

|Tier | Number of tests | Time spent |
|:--:|:--:|:--:|
| 0 | 122 | 6m24s |

## List of configuration tests

- **[Test basic configuration target](test_basic_configuration_target.md)**: Check if `wazuh-logcollector` 
  fails using invalid `connection` values.

- **[Test basic configuration reconnect time](test_basic_configuration_reconnect_time.md)**: Check if wazuh-remoted 
  fails using invalid `connection` values.

- **[Test basic configuration query](test_basic_configuration_query.md)**: Check if wazuh-remoted 
  fails using invalid `connection` values.
  
- **[Test basic configuration out format](test_basic_configuration_out_format.md)**: Check if wazuh-remoted 
  fails using invalid `connection` values.
  
- **[Test basic configuration only future events](test_basic_configuration_only_future_events.md)**: Check if wazuh-remoted 
  fails using invalid `connection` values.
  
- **[Test basic configuration log format](test_basic_configuration_log_format.md)**: Check if wazuh-remoted 
fails using invalid `connection` values.

- **[Test basic configuration location](test_basic_configuration_location.md)**: Check if wazuh-remoted 
fails using invalid `connection` values.

- **[Test basic configuration label](test_basic_configuration_label.md)**: Check if wazuh-remoted 
fails using invalid `connection` values.

- **[Test basic configuration ignore binaries](test_basic_configuration_ignore_binaries.md)**: Check if wazuh-remoted 
fails using invalid `connection` values.
  
- **[Test basic configuration frequency](test_basic_configuration_frequency.md)**: Check if wazuh-remoted 
fails using invalid `connection` values.
  
- **[Test basic configuration exclude](test_basic_configuration_exclude.md)**: Check if wazuh-remoted 
fails using invalid `connection` values.
  
- **[Test basic configuration command](test_basic_configuration_command.md)**: Check if wazuh-remoted 
fails using invalid `connection` values.
  
- **[Test basic configuration alias](test_basic_configuration_alias.md)**: Check if wazuh-remoted 
fails using invalid `connection` values.
  
- **[Test basic configuration age](test_basic_configuration_age.md)**: Check if wazuh-remoted 
fails using invalid `connection` values.

