# Test max files per second

This test checks the FIM behavior when the option `max_files_per_second` is enabled/disabled.

## General info

| Tier | Platforms | Time spent| Test file |
|:--:|:--:|:--:|:--:|
| 1 | Linux, Windows, MacOS, Solaris | 00:00:40 | [test_max_files_per_second.py](../../../../../../tests/integration/test_fim/test_files/test_max_files_per_second/test_max_files_per_second.py)|

## Test logic
- After the baseline is generated, the test will create files inside a monitored folder.
- Finally, if the option `max_files_per_second` is configured, the test will check that FIM sleeps for one second.
## Checks

- [x] Checks that FIM sleeps once the maximum files per second is reached.
- [x] Checks that FIM doesn't sleeps if `max_files_per_second` is not enabled.

## Execution result

```
python3 -m pytest test_max_files_per_second/
============================= test session starts ==============================
platform linux -- Python 3.8.5, pytest-6.2.2, py-1.10.0, pluggy-0.13.1
rootdir: /vagrant/wazuh-qa/tests/integration, configfile: pytest.ini
plugins: html-2.0.1, testinfra-5.0.0, metadata-1.11.0
collected 6 items

test_max_files_per_second/test_max_files_per_second.py ......                                                                                                                                                                         [100%]

============================================================================================================ 6 passed in 42.96s =============================================================================================================
```

## Code documentation

::: tests.integration.test_fim.test_files.test_max_files_per_second.test_max_files_per_second
