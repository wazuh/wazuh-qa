# Test intervals:request_timeout API's option

## Overview 

Check that the `request_timeout` option of the API does not cause any bug in the API itself and ensures its functionality.

## Objective

Check the correct functionality of the `request_timeout` option.

## General info

|Tier | Number of tests | Time spent |
|:--:|:--:|:--:|
| 0 | 1 | 17.51s |

## Expected behavior

- Fail if a timeout error is not returned.

## Code documentation

::: tests.integration.test_api.test_config.test_request_timeout.test_request_timeout
