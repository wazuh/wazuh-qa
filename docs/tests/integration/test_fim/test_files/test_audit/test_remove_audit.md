# Test remove audit

The test checks that if audit is not installed, FIM switches from `whodata` to `realtime`.

## General info

| Tier | Platforms | Time spent| Test file |
|:--:|:--:|:--:|:--:|
| 1 | Linux | 00:00:05 | [test_remove_rule_five_times.py](../../../../../../tests/integration/test_fim/test_files/test_audit/test_remove_rule_five_times.py)|

## Test logic

- The test will uninstall `auditd`.
- The test will check that FIM is able to switch from `whodata` to `realtime`.
- Finally, the test will install again `auditd`

## Checks

- [x] Checks that FIM is able to switch from `whodata` to `realtime` if auditd is not installed.

## Execution result

```
python3 -m pytest test_files/test_audit/test_remove_audit.py
======================================================= test session starts ========================================================
platform linux -- Python 3.8.5, pytest-6.2.2, py-1.10.0, pluggy-0.13.1
rootdir: /vagrant/wazuh-qa/tests/integration, configfile: pytest.ini
plugins: html-2.0.1, testinfra-5.0.0, metadata-1.11.0
collected 1 item

test_files/test_audit/test_remove_audit.py .                                                                                 [100%]

======================================================== 1 passed in 5.95s =========================================================
```

## Code documentation

::: tests.integration.test_fim.test_files.test_audit.test_remove_audit
