# Overview

Wazuh remoted is the daemon that listen for external connections to Wazuh manager (agents and syslogs devices). 

## Tiers
### Tier 0
#### Test configuration

For each configuration option, we check if remoted correctly starts and that any api request to the Manager configuration returns the same options that the specified in ossec.conf

#### Test communications through the sockets

These tests will cover the messages sent through the sockets by wazuh-remoted and the agents. Using these sockets, the agent can send messages to the manager and vice versa.

- **Ping-pong messages**: these messages are sent from the agent to the manager to check if the manager is ready to receive and send messages.  

