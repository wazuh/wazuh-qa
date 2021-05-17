# Test complex wildcards

The test check for the correct expansion of complex wildcards in syscheck directories path definition including wildcards expansion in both root folders and subdirectories.

## General info

| Tier | Platforms | Time spent| Test file |
|:--:|:--:|:--:|:--:|
| 1 | Linux | 1109s |
| 1 | Windows | 569s |

## Test logic

The test creates a group of root directories and subdirectories that match comples wildcards expressions and other that doesn't match the expressions set in syscheck directories to be monitored. Then, the test will create, modify and delete files inside a folder passed as argument. The test will expect fim events only if the folder where the changes are made matches the expression previously set under syscheck stanza.

## Execution result

```
=========================================================================================== test session starts ===========================================================================================
platform linux -- Python 3.6.9, pytest-6.2.4, py-1.10.0, pluggy-0.13.1
rootdir: /home/vagrant/wazuh-qa/tests/integration, configfile: pytest.ini
plugins: metadata-1.11.0, html-2.0.1, testinfra-6.0.0, testinfra-6.3.0
collected 84 items

test_wildcards_complex.py ....................................................................................                                                                                      [100%]

-------------------------------------------------------------------------- generated html file: file:///vagrant/html_report.html --------------------------------------------------------------------------
===================================================================================== 84 passed in 1109.08s (0:18:29) =====================================================================================
```

## Code documentation

::: tests.integration.test_fim.test_files.test_wildcards_complex.test_wildcards_complex
