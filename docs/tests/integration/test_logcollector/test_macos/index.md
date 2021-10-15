# Test macOS

## Overview 

Wazuh macOS agent allows gathering unified logging system events. These tests ensure logcollector works correctly with 
this kind of log format. Also, these tests check that every option available for this log format work as expected.

## Objective

Confirm that logcollector works correctly for unified logging system events in macOS agent.

## General info

|Tier | Total | Time spent |
| :--:| :--:  | :--:       |
| 0   |    4 |    3m40s   |


## List of tests

- **[Test macOS format basic](test_macos_format_basic.md)**: Check if `wazuh-logcollector` correctly gather generated 
unified logging system events.

- **[Test macos format query](test_macos_format_query.md)**: Check if `query` option for `wazuh-logcollector`
  works correctly for macos log format.

- **[Test macOS format only future events](test_macos_format_only_future_events.md)**: Check if `only-future-events`
  works correctly for macOS log format.
  
- **[Test macOS multiline values](test_macos_multiline_values.md)**: Check if `wazuh-logcollector` correctly collects multiline events from the unified logging system.

- **[Test macOS log process](test_macos_log_process.md)**: Check `log stream` process has been killed when
Wazuh agent stops.
