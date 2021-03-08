# Overview

**Wazuh-db** is the daemon in charge of the databases with all the Wazuh persistent information, exposing a socket so receive requests and provide information.

## Tiers
### Tier 0
#### Test wazuh_db

These tests check the Wazuh-db commands syntax, valid responses and error messages in different circumstances. They are divided in **.yaml** configuration files:

- **agent_messages.yaml**: tests for agents in general, currently only for Agents' CVEs table
- **fim_messages.yaml**: tests for agents, but only for FIM module
- **global_messages.yaml**: tests for the Global DB, using "global" commands