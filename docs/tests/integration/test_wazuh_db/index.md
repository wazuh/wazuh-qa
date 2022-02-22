# Overview

**Wazuh-db** is the daemon in charge of the databases with all the Wazuh persistent information, exposing a socket to receive requests and provide information.

## Tiers
### Tier 0
#### Test wazuh_db

The main test case, test_wazuh_db_messages, checks the Wazuh-db commands syntax, valid responses, and error messages in different circumstances. They are divided into **.yaml** configuration files:

- **agent_messages.yaml**: tests for agents DB, general commands
- **fim_messages.yaml**: tests for agents DB, FIM module commands
- **global_messages.yaml**: tests for the Global DB, using `global` commands

The test case `test_wazuh_db_create_agent`, checks the correct creation of a new agent DB when a query with a new agent ID is sent.

The test case `test_wazuh_db_chunks`, checks that commands by chunks work properly when agents amount exceed the response maximum size.

The test case `test_wazuh_db_range_checksum`, checks the checksum range correct behavior during the synchronization of the DB.
- **syscollector_deltas_messages.yaml**: tests for agents DB, Syscollector deltas (dbsync) commands
