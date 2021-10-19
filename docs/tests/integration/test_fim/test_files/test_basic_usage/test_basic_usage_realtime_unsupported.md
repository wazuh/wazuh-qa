# Test basic usage realtime unsupported

The test checks for FIM to properly change from realtime to scheduled mode when it is not supported.

## General info

| Tier | Platforms | Time spent | Test file |
|:--:|:--:|:--:|:--:|
| 0 | Macos | 4s | test_basic_usage_realtime_unsupported.py
| 0 | Solaris | 5s | test_basic_usage_realtime_unsupported.py

## Test logic

The test performs a CUD set of operations to a file with realtime mode set as the monitoring option in ossec.conf. Firstly
the test checks for the initial realtime event appearing in the logs and if the current OS does not support it then wait
for the initial FIM scan mode. After that, the set of operations takes place and the expected behavior is the events
will be generated with scheduled mode and not realtime as it is set in the configuration.

## Execution result

```
============================= test session starts ==============================
platform sunos5 -- Python 3.7.6, pytest-6.2.3, py-1.10.0, pluggy-0.13.1 -- /opt/python3/bin/python3
cachedir: .pytest_cache
metadata: {'Python': '3.7.6', 'Platform': 'SunOS-5.11-i86pc-i386-32bit-ELF', 'Packages': {'pytest': '6.2.3', 'py': '1.10.0', 'pluggy': '0.13.1'}, 'Plugins': {'html': '3.1.1', 'metadata': '1.8.0', 'testinfra': '5.0.0'}}
rootdir: /tmp/Test_integration_B7150_20210701111105/tests/integration, configfile: pytest.ini
plugins: html-3.1.1, metadata-1.8.0, testinfra-5.0.0
collecting ... collected 1 item

test_fim/test_files/test_basic_usage/test_basic_usage_realtime_unsupported.py::test_realtime_unsupported[get_configuration0-check_realtime_mode_failure0-testfile.txt-/dir] PASSED [100%]

- generated html file: file:///tmp/Test_integration_B7150_20210701111105/report.html -
============================== 1 passed in 5.87s ===============================

============================= test session starts ==============================
platform darwin -- Python 3.7.3, pytest-6.2.3, py-1.10.0, pluggy-0.13.1 -- /Library/Developer/CommandLineTools/usr/bin/python3
cachedir: .pytest_cache
metadata: {'Python': '3.7.3', 'Platform': 'Darwin-19.0.0-x86_64-i386-64bit', 'Packages': {'pytest': '6.2.3', 'py': '1.10.0', 'pluggy': '0.13.1'}, 'Plugins': {'testinfra': '5.0.0', 'html': '3.1.1', 'metadata': '1.8.0'}}
rootdir: /private/tmp/Test_integration_B7150_20210701111105/tests/integration, configfile: pytest.ini
plugins: testinfra-5.0.0, html-3.1.1, metadata-1.8.0
collecting ... collected 1 item

test_fim/test_files/test_basic_usage/test_basic_usage_realtime_unsupported.py::test_realtime_unsupported[get_configuration0-check_realtime_mode_failure0-testfile.txt-/private/var/root/dir] PASSED [100%]

- generated html file: file:///tmp/Test_integration_B7150_20210701111105/report.html -
============================== 1 passed in 4.76s ===============================
```

## Code documentation

::: tests.integration.test_fim.test_files.test_basic_usage.test_basic_usage_realtime_unsupported
