# Test basic configuration
## Overview 
Configuration tests check that the introduced configuration on ossec.conf works as expected and no valid option generates errors. 
Also, it checks that the API answer for configuration requests coincides with the configuration introduced in ossec.conf

## Objective

Confirm that the different options for remoted configuration work and are correctly loaded.

## General info

|Tier | Number of tests | Time spent |
|:--:|:--:|:--:|
| 0 | 1 | 10s |

## Expected behavior

- Fail if remoted doesn't start with a valid configuration
- Fail if remoted fails with a valid configuration (error|critical)
- Fail if API query `{protocol}://{host}:{port}/manager/configuration?section=remote` doesn't match the introduced configuration on ossec.conf 

## Testing

- Basic configuration: connection, port, protocol

## Code documentation
::: tests.integration.test_remoted.test_configuration.test_basic_configuration_connection_valid
