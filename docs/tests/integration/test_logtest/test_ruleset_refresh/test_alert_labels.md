# Test logtest - rules labels

## Overview

Check that after modifying the alert level it takes effect when opening a new
logtest sessions, without having to reset the manager.

## Objective

- To confirm that, when using the default alert level, a log under
test, that should trigger an alert when being analyzed with `logtest`, does
indeed trigger an alert.
- To confirm that, when using the default alert level, a log under
test, that should not trigger an alert when being analyzed with `logtest`, does
not trigger any alert.
- To confirm that, when using a custom alert level, a log under
test, that should trigger an alert when being analyzed with `logtest`, does
indeed trigger an alert, without having to reset the manager.
- To confirm that, when using a custom alert level, a log under
test, that should not trigger an alert when being analyzed with `logtest`, does
not trigger any alert, without having to reset the manager.

## General info

|Tier | Total | Time spent |
| :--:| :--:  | :--:       |
| 0   |    4 |    3s  |

## Expected behavior

- Fail if `wazuh-analysisd` is not running
- Fail if `wazuh-analysisd` returns an error
- Fail if `wazuh-analysisd` does not trigger an alert when, according to the alert level, it should do so
- Fail if `wazuh-analysisd` does trigger an alert when, according to the alert level, it should not do so

## Code documentation

::: tests.integration.test_logtest.test_ruleset_refresh.test_alert_labels
