# Test execd

## Overview 

Active responses execute a script in response to the triggering of specific alerts
based on the alert level or rule group.
`wazuh-execd` runs Active Responses by initiating the configured scripts.

These tests check if `wazuh-execd` executes the active responses correctly.

## Objective

Check if the Active Response scripts are executed correctly by `execd`.

## General info

|Tier | Number of tests | Time spent |
|:--:|:--:|:--:|
| 0 | 2 | 0m 21s |

## List of execd tests

- **[Test firewall-drop](test_execd_firewall_drop.md)**: Check if the `firewall-drop` script is properly working.

- **[Test restart-wazuh](test_execd_restart.md)**: Check if the `restart-wazuh` script is properly working.