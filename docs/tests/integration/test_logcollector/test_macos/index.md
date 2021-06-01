# Test macOS

## Overview 

Wazuh macOS agent allow gather unnified logging system events. These tests ensure logcollector works correctly with this
kind of log format. Also, these tests check that every option available for this log format work as expected.

## Objective

Confirm that logcollector works correctly for unnified logging system events in macOS agent.

## General info

|Tier | Total | Time spent |
| :--:| :--:  | :--:       |
| 0   |    4 |    54s   |


## List of tests

- **[Test macos format basic](test_macos_format_basic.md)**: Check if `wazuh-logcollector` gather corrrectly generated 
unnified logging system events.
    
- **[Test macos format only future events](test_macos_format_only_future_events.md)**: Check if `only-future-events`
  works correctly for macos log format.