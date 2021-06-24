# Test max_upload_size API option

## Overview 

Verify that a 413 status code (Request Entity Too Large) is returned if the body in an API request is bigger than `max_upload_size`, which is specified in the `api.yaml` file.

## Objective

- To confirm that `max_upload_size` is correctly applied so requests with bigger bodies can't be run.

## General info

| Number of tests | Time spent |
|:--:|:--:|
| 2 | 33s |

## Expected behavior

- Fail if 200 code is returned when body is bigger than `max_upload_size`.
- Fail if 413 code is returned when body is smaller than `max_upload_size`.

## Code documentation

::: tests.integration.test_api.test_config.test_max_upload_size.test_max_upload_size
