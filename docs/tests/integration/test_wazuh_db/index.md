# Overview

**Wazuh-db** is the daemon in charge of the databases with all the Wazuh persistent information, exposing a socket to receive requests and provide information.

## Tiers
### Tier 0
#### Test wazuh_db

These tests check the Wazuh-db commands syntax, valid responses and error messages in different circumstances. They are divided in **.yaml** configuration files:

- **agent_messages.yaml**: tests for agents DB, general commands
- **fim_messages.yaml**: tests for agents DB, FIM module commands
- **global_messages.yaml**: tests for the Global DB, using `global` commands