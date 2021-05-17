# Test duplicated regitry entries

This test will check that for two monitored registries with the same name value but with different capitalisation only triggers one added event when the registry is created.

## General info

|Tier | Number of tests | Time spent|
|:--:|:--:|:--:|
| 0 | 1 | 15s |

## Test logic

The test monitor two registries with the same path but different capitalization. It creates
one registry with the path being one of the two registries monitorized and then tries to grab
one added event for the registry creation. Finally it tries to grab the added event one second
time but it should rise one TimeoutError to ensure only one added event was sent.

## Execution result
```
python3 -m pytest test_files/test_registry/test_registry_basic_usage/test_basic_usage_registry_duplicated_entries.py
============================================================== test session starts ==============================================================
platform win32 -- Python 3.7.3, pytest-5.1.2, py-1.8.0, pluggy-0.13.0
rootdir: C:\Users\jmv74211\Desktop\wazuh-qa\tests\integration, inifile: pytest.ini
plugins: html-2.0.1, metadata-1.10.0, testinfra-5.0.0
collected 1 item

test_basic_usage_registry_duplicated_entries.py .                                                                                          [100%]

------ generated html file: file://C:\Users\jmv74211\Desktop\wazuh-qa\tests\integration\test_fim\test_registry\report_dupl_reg_master.html ------
============================================================== 1 passed in 15.02s ===============================================================
```

## Code documentation

::: tests.integration.test_fim.test_registry.test_registry_basic_usage.test_basic_usage_registry_duplicated_entries
