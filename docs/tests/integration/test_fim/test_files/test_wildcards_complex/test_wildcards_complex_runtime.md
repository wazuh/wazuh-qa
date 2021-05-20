# Test complex wildcards
In every scan, FIM looks for any new folder that matches a configured wildcard expression. This test checks this
functionality using complex wildcards expression (expressions that may match a given subdirectory, all subdirectories, etc).

## General info

| Tier | Platforms | Time spent| Test file |
|:--:|:--:|:--:|:--:|
| 1 | Linux, windows | 1503s | test_wildcards_complex_runtime.py

## Test logic
The test will configure wildcards expressions and will create an empty folder. Once that FIM has started and the
baseline scan is completed, the test will create folders that may match a configured expression and will wait until
the wildcards are expanded again (in the next scan). Once the wildcards are reloaded, the test will create, modify and
delete files inside those folders. The test will wait for events of a folder only if it matches a configured expression.
## Execution result

```
root@ubuntumanager:/vagrant/wazuh-qa/tests/integration/test_fim/test_files/test_wildcards_complex# python3 -m pytest test_wildcards_complex_runtime.py
==================================================================== test session starts ====================================================================
platform linux -- Python 3.8.5, pytest-6.2.3, py-1.10.0, pluggy-0.13.1
rootdir: /vagrant/wazuh-qa/tests/integration, configfile: pytest.ini
plugins: testinfra-5.0.0, metadata-1.11.0, html-3.1.1
collected 18 items

test_wildcards_complex_runtime.py ..................                                                                                                  [100%]

============================================================== 18 passed in 454.13s (0:07:34) ===========
```

## Code documentation

::: tests.integration.test_fim.test_files.test_wildcards_complex.test_wildcards_complex_runtime
