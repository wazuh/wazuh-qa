# Test only future events for macos format

## Overview 

Check if `only-future-events` option for `logcollector` works correctly for macos unified logging 
system format (ULS).

## Objective

- To confirm that `logcollector` gather all events from ULS when `only-future-events` is disabled
- To confirm that `logcollector` does not gather old events when `only-future-events` is enabled

## General info

|Tier | Number of tests | Time spent |
|:--:|:--:|:--:|
| 0 | 2 | 2m55s |

## Expected behavior

- Fail if `logcollector` does not read correctly macOS ULS log stream.
- Fail if `logcollector` does not gather correctly first ULS log.
- Fail if `logcollector` gather old ULS log when `only-future-events` is enabled.
- Fail if `logcollector` does not gather old ULS log when `only-future-events` is disabled.
- Fail if `logcollector` does not gather new ULS logs.

## Code documentation

::: tests.integration.test_logcollector.test_macos.test_macos_format_only_future_events