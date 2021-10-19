# Test location - Location
## Overview 

Check if logcollector works properly with different locations.

## Objective

- To confirm the logcollector works correctly with single path locations.
- To confirm the logcollector works correctly with wildcard path locations.

## General info

|Tier | Number of tests | Time spent |
|:--:|:--:|:--:|
| 0 | 11 | 23.77s |

## Expected behavior

- Pass if logcollector analyzes a single file.
- Pass if logcollector analyzes a single file with multiple directory depth.
- Pass if logcollector analyzes a single file with multiple directory depth.
- Pass if logcollector shows an error message for a non-existent file.
- Pass if logcollector analyzes files in a wildcard path.
- Pass if logcollector analyzes a file with white spaces.
- Pass if logcollector analyzes a file with right wildcard.
- Pass if logcollector analyzes s file that contains a wildcard.
- Pass if logcollector shows a warning message for duplicated files.
- Pass if logcollector analyzes a file with the date.
- Pass if logcollector shows a warning message when the file limit has been reached.

## Code documentation

::: tests.integration.test_logcollector.test_location.test_location
