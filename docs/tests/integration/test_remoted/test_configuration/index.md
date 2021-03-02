# Test basic configuration

## Overview 

These tests check if the introduced configuration in the ossec.conf works as expected for valid values and if the API 
response for configuration requests coincides with the one introduced in the ossec.conf.

For invalid ones, it checks if `wazuh-remoted` returns the expected error message.

## Objective

Confirm that the different options for remoted configuration work and are correctly loaded.

## General info

|Tier | Number of tests | Time spent |
|:--:|:--:|:--:|
| 0 | 17 | 2m 14s |

## List of configuration tests

- **[Test invalid connection](test_basic_configuration_connection_invalid_connection.md)**: Check if wazuh-remoted 
  fails using invalid `connection` values.


- **[Test valid connection](test_basic_configuration_connection_valid.md)**: Check if wazuh-remoted correctly starts
  using valid `protocol` values.


- **[Test invalid port](test_basic_configuration_connection_invalid_port.md)**: Check if wazuh-remoted fails using 
  invalid `port` values.
  

- **[Test invalid protocol](test_basic_configuration_connection_invalid_protocol.md)**: Check if wazuh-remoted 
  correctly starts using invalid `protocol` values.


- **[Test ipv6 valid](test_basic_configuration_ipv6.md)**: Check if wazuh-remoted correctly starts 
  using valid `ipv6` values.


- **[Test local_ip invalid](test_basic_configuration_local_ip_invalid.md)**: Check if wazuh-remoted fails using 
  invalid `local_ip` values.


- **[Test local_ip valid](test_basic_configuration_local_ip_valid.md)**: Check if wazuh-remoted correctly starts 
  using valid `local_ip` values.


- **[Test queue size syslog](test_basic_configuration_queue_size_syslog.md)**: Check if wazuh-remoted fails using 
  valid `queue_size` along with `syslog` connection.
  

- **[Test queue size too big](test_basic_configuration_queue_size_too_big.md)**: Check if wazuh-remoted correctly
  shows warning message using a too big `queue_size` value.


- **[Test queue size valid](test_basic_configuration_queue_size_valid.md)**: Check if wazuh-remoted correctly starts 
  using valid `queue_size` values.
  

- **[Test rids closing time invalid](test_basic_configuration_rids_closing_time_invalid.md)**: Check if wazuh-remoted 
  fails using invalid `rids_closing_time` values. 


- **[Test rids closing time valid](test_basic_configuration_rids_closing_time_valid.md)**: Check if wazuh-remoted 
  correctly starts using valid `rids_closing_time` values.


- **[Test syslog allowed denied ips valid](test_basic_configuration_syslog_allowed_denied_ips_valid.md)**: Check if 
  wazuh-remoted correctly starts using valid ip addresses for `allowed-ips` and `denied-ips` options.


- **[Test syslog denied ips](test_basic_configuration_syslog_denied_ips.md)**: Check if wazuh-remoted correctly 
  denies ip for `syslog` connection.


- **[Test syslog allowed ips invalid](test_basic_configuration_syslog_allowed_ips_invalid.md)**: Check if 
  wazuh-remoted fails using invalid `allowed_ips`  values. 
  

- **[Test syslog denied ips invalid](test_basic_configuration_syslog_denied_ips_invalid.md)**: Check if wazuh-remoted 
  fails using invalid `denied_ips`  values.


- **[Test syslog no allowed ips provided](test_basic_configuration_syslog_no_allowed_ips.md)**: Check if wazuh-remoted 
  fails using if no `allowed_ips`  value is provided.