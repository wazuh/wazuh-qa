# Overview

Wazuh remoted is the daemon that listen for external connections to Wazuh manager (agents and syslogs devices). 

## Tiers
### Tier 0
#### Test configuration

For each configuration option, we check if remoted correctly starts and that any api request to the Manager configuration returns the same options that the specified in ossec.conf

