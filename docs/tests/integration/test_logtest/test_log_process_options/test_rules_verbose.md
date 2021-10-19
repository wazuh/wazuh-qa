# Test log process options - Rules verbose
## Overview 

Check if `wazuh-logtest` works correctly in `verbose` mode for rules debugging

## Objective

- To confirm that `wazuh-logtest` does not do rule debugging when the rules_debug field is omitted
- To confirm that `wazuh-logtest` does not do rule debugging when the rules_debug field is set to false
- To confirm that `wazuh-logtest` does not do rule debugging when the rules_debug field is set to a bad type (string)
- To confirm that `wazuh-logtest` does not do rule debugging when the rules_debug field is set to a bad type (number)
- To confirm that `wazuh-logtest` does not do rule debugging when the rules_debug field is set to a bad type (object)
- To confirm that `wazuh-logtest` does not do rule debugging when the rules_debug field is set to a bad type (array)
- To confirm that `wazuh-logtest` does not do rule debugging when the options field is set to a bad type (boolean)
- To confirm that `wazuh-logtest` does not do rule debugging when the options field is set to a bad type (array)
- To confirm that `wazuh-logtest` does not do rule debugging when the options field is set to a bad type (number)
- To confirm that `wazuh-logtest` does not do rule debugging when the options field is set to a bad type (string)
- To confirm that `wazuh-logtest` does rule debugging when the rules_debug field is set to true

## General info

|Tier | Number of tests | Time spent |
|:--:|:--:|:--:|
| 0 | 11 | 10s |

## Expected behavior

- Pass if `wazuh-logtest` returns rule debugging information when parameters are correct
- Pass if `wazuh-logtest` does not return rule debugging information when parameters are incorrect.

## Code documentation

::: tests.integration.test_logtest.test_options.test_log_process_options.test_rules_verbose
