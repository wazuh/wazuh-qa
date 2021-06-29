# Test Logtest

## Overview

Wazuh-Logtest allows testing and verifying rules and decoders and it is based on
the use of unique sessions where each session loads its own rules and decoders.
These tests ensure that logtest works correctly under different scenarios and
that every option available work as expected.

## Tiers

### Tier 0

#### Test configuration

- Check that `logtest` works as expected under different pre-defined
configurations that either produce the logtest to correctly start; to be
disabled or to log an error.

- Check that `analisysd` correctly retrieves the pre-defined configurations that
are set.

#### Test invalid rule decoders syntax

- Check that `logtest` correctly detects and handles errors when processing a
rules file.

- Check that `logtest` correctly detects and handles errors when processing a
decoders file.

#### Test invalid socket input

- Check that `logtest` correctly detects and handles errors when sending a
message through the socket to `analysisd`.

#### Test invalid token

- Check that `logtest` correctly detects and handles errors when using a token.

#### Test remove old sessions

- Check that `logtest` correctly detects and handles the situation where trying
to use more sessions than allowed and then the oldest session is released.

- Check that `logtest` correctly detects and handles the situation where trying
to use more sessions than allowed and then old sessions are released due to
inactivity.

#### Test remove session

- Check that `logtest` correctly detects and removes the sessions under
pre-defined scenarios.

#### Test rules decoders load

- Check that modifying the decoders configuration allows new `logtest` sessions
to test different sets of decoders withouth having to restart the manager.

- Check that modifying the rules configuration allows new `logtest` sessions
to test different sets of rules withouth having to restart the manager.
