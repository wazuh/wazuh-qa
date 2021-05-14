# Test basic usage wildcards

The test check for the correct expansion of wildcards in syscheck directories path definition.

## General info

| Tier | Platforms | Time spent| Test file |
|:--:|:--:|:--:|:--:|
| 0 | Linux | 85s |
| 0 | Windows | 142s |

## Test logic

The test creates a group of directories that match wildcards expressions and other that
doesn't match the expressions set in syscheck directories to be monitored. Then, the test will create, modify and delete files inside a folder. The test will expect events only if the folder where the changes are made matches the configured expresion

## Execution result

```
=========================================================================================== test session starts ===========================================================================================
platform linux -- Python 3.6.9, pytest-6.2.4, py-1.10.0, pluggy-0.13.1
rootdir: /home/vagrant/wazuh-qa/tests/integration, configfile: pytest.ini
plugins: metadata-1.11.0, html-2.0.1, testinfra-6.0.0, testinfra-6.3.0
collected 9 items

wazuh-qa/tests/integration/test_fim/test_files/test_basic_usage/test_basic_usage_wildcards.py .........                                                                                             [100%]

-------------------------------------------------------------------------- generated html file: file:///vagrant/html_report.html --------------------------------------------------------------------------
====================================================================================== 9 passed in 85.37s (0:01:25) =======================================================================================
```

## Code documentation

::: tests.integration.test_fim.test_files.test_basic_usage.test_basic_usage_wildcards
