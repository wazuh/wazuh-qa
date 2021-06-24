# Test location - Exclude
## Overview 

Check if logcollector works properly with different exclude and location values.

## Objective

- To confirm the logcollector excludes the required files and analyze the others.

## General info

|Tier | Number of tests | Time spent |
|:--:|:--:|:--:|
| 0 | 10 | 20.63s |

## Expected behavior

- Pass if logcollector exclude files with a left wildcard.
- Pass if logcollector exclude files with a right wildcard.
- Pass if logcollector exclude files with left and right wildcard.
- Pass if logcollector exclude files in wildcard location.

## Code documentation

::: tests.integration.test_logcollector.test_location.test_location_exclude
