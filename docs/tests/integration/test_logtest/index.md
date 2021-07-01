# Test Logtest

## Overview

Wazuh-Logtest allows testing and verifying rules and decoders and it is based on
the use of unique sessions where each session loads its own rules and decoders.
These tests ensure that logtest works correctly under different scenarios and
that every option available work as expected.

## Tiers

### Tier 0

#### Test configuration

- **[Test configuration file](test_configuration/test_configuration_file.md)**:
Check if `wazuh-logtest` works as expected under different pre-defined
configurations that either produce the logtest to correctly start; to be
disabled or to log an error.

- **[Test get configuration sock](test_configuration/test_get_configuration_sock.md)**:
Check if `wazuh-analisysd` correctly retrieves the `rule_test` configuration.

#### Test invalid socket input

- **[Test invalid socket input](test_invalid_socket_input/test_invalid_socket_input.md)**:
Check if `wazuh-logtest` correctly detects and handles errors when sending a
message through the socket to `analysisd`.

#### Test invalid token

- **[Test invalid token](test_invalid_token/test_invalid_session_token.md)**:
Check if `wazuh-logtest` correctly detects and handles errors when using a token.

#### Test remove session

- **[Test remove session](test_remove_session/test_remove_session.md)**:
Check if `wazuh-logtest` correctly detects and removes the sessions under
pre-defined scenarios.

#### Test rules decoders load

- **[Test load rules decoders](test_rules_decoders_load/test_load_rules_decoders.md)**:
Check if `wazuh-logtest` produce the correct rule/decoder matching.
#### Test ruleset refresh
#### Test cdb labels

- Check that `logtest` works as expected with the operation of 
loading new cdb list files without the need to restart the manager.
