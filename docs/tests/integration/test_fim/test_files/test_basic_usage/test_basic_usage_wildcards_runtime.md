# Test basic usage wildcards runtime
In every scan, FIM looks for any new folder that matches a configured wildcard expression. This test checks this
functionality using simple wildcards expressions.

## General info

| Tier | Platforms | Time spent| Test file |
|:--:|:--:|:--:|:--:|
| 0 | Linux, windows | 248s | test_basic_usage_wildcards_runtime.py

## Test logic
The test will configure wildcards expressions and will create an empty folder. Once that FIM has started and the
baseline scan is completed, the test will create folders that may match a configured expression and will wait until
the wildcards are expanded again (in the next scan). Once the wildcards are reloaded, the test will create, modify and
delete files inside those folders. The test will wait for events of a folder only if it matches a configured expression.
## Execution result

```
root@ubuntumanager:/vagrant/wazuh-qa/tests/integration/test_fim/test_files/test_basic_usage# python3 -m pytest test_basic_usage_wildcards_runtime.py
==================================================================== test session starts ====================================================================
platform linux -- Python 3.8.5, pytest-6.2.3, py-1.10.0, pluggy-0.13.1
rootdir: /vagrant/wazuh-qa/tests/integration, configfile: pytest.ini
plugins: testinfra-5.0.0, metadata-1.11.0, html-3.1.1
collected 9 items

test_basic_usage_wildcards_runtime.py .........                                                                                                       [100%]

=============================================================== 9 passed in 247.79s (0:04:07) ===============================================================

```

## Code documentation

::: tests.integration.test_fim.test_files.test_basic_usage.test_basic_usage_wildcards_runtime
