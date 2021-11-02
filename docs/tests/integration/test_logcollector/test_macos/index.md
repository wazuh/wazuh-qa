# Test macOS

## Overview

Wazuh macOS agent allows gathering unified logging system events. These tests ensure logcollector works correctly with
this kind of log format. Also, these tests check that every option available for this log format work as expected.

## Objective

Confirm that logcollector works correctly for unified logging system events in macOS agent.

## General info

|Tier | Total | Time spent |
| :--:| :--:  | :--:       |
| 0   |    4 |    5m20s   |

## List of tests

- **[Test macOS file status basic](test_macos_file_status_basic.md)**: Checks if `wazuh-logcollector` correctly
generates the `file_status.json` file used by `only future events`.

- **[Test macOS file status predicate](test_macos_file_status_predicate.md)**: Checks that `wazuh-logcollector` does not
store "macos"-formatted localfile data in `file_status.json`, since its predicate is erroneous.

- **[Test macOS file status when no macos](test_macos_file_status_when_no_macos.md)**: Checks that `wazuh-logcollector`
does not store and removes, if exists, previous "macos"-formatted localfile data in the file_status.json

- **[Test macOS format basic](test_macos_format_basic.md)**: Check if `wazuh-logcollector` correctly gather generated 
unified logging system events.

- **[Test macos format query](test_macos_format_query.md)**: Check if `query` option for `wazuh-logcollector`
  works correctly for macos log format.

- **[Test macOS format only future events](test_macos_format_only_future_events.md)**: Check if `only-future-events`
  works correctly for macOS log format.
  
- **[Test macOS multiline values](test_macos_multiline_values.md)**: Check if `wazuh-logcollector` correctly collects multiline events from the unified logging system.

- **[Test macOS log process](test_macos_log_process.md)**: Check `log stream` process has been killed when
Wazuh agent stops.
