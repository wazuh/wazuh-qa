# Test only future events

## Overview 

These tests check if the logcollector `only-futurel-events` option work as expected.

## Objective

Confirm that when `only-future-events` is enabled, `logcollector` only gather new events. Otherwise, if if 
`only-future-events` is disabled, `logcollector` should gather all generated event in specified `location`.

## General info

|Tier | Number of tests | Time spent |
|:--:|:--:|:--:|
| 0 | 21 | 42.20s |

## List of configuration tests

- **[Test macos format only future events](test_macos_format_only_future_events.md)**: Check if `only-future-events`
  works correctly for macos log format.

- **[Test only future events](test_only_future_events.md)**: Check that `logcollector` continues to monitor log 
  files after they have been rotated.