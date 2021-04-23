# Test duplicated regitry entries

This test will check that for two monitored registries with the same name value but with different capitalisation only triggers  one modified event when the registry is changed.

## General info

|Tier | Number of tests | Time spent| Test file |
|:--:|:--:|:--:|:--:|
| 0 | 1 | 0:0:25 | [test_basic_usage_registry_duplicated_entries.py](../../../../../../tests/integration/test_fim/test_registry/test_registry_basic_usage/test_basic_usage_registry_duplicated_entries.py)|

## Test logic

The test creates two registries with the same name but different capitalisation,
and then modifies one of them and wait for the monitor to grab that event.
The second call to the monitor should arise TimeoutError to be succesful. This test
ensures the windows agent doesn't duplicate alerts due to windows being case insensitive.


## Execution result
python3 -m pytest test_files/test_registry/test_registry_basic_usage/test_basic_usage_registry_duplicated_entries.py
```
===================================================================================== test session starts =====================================================================================
platform win32 -- Python 3.8.1, pytest-6.2.2, py-1.10.0, pluggy-0.13.1
rootdir: C:\Users\vagrant\Desktop\wazuh-qa\tests\integration, configfile: pytest.ini
plugins: html-2.0.1, metadata-1.11.0, testinfra-6.2.0, testinfra-6.0.0
collected 1 item

test_basic_usage_registry_duplicated_entries.py  .                                                                                                                           [100%]

=================================================================================== 1 passed in -46763.03s ====================================================================================
```

## Code documentation

::: tests.integration.test_fim.test_registry.test_registry_basic_usage.test_basic_usage_registry_duplicated_entries
