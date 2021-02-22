# Test audit remove rule five times

The test checks that FIM stops monitoring with `whodata` when at least 5 manipulation in the audit rules has been done by a user.

## General info

| Tier | Platforms | Time spent| Test file |
|:--:|:--:|:--:|:--:|
| 1 | Linux | 00:00:06 | [test_remove_rule_five_times.py](../../../../../../tests/integration/test_fim/test_files/test_audit/test_remove_rule_five_times.py)|

## Test logic

- The test will monitor a folder using `whodata`.
- The test will modify five times the audit rules and it will check that `whodata` switches to `realtime` .

## Checks

- [x] Checks that FIM is able to switch from `whodata` to `realtime` when an user edits the audit rules.

## Execution result

```
python3 -m pytest test_files/test_audit/test_remove_rule_five_times.py
======================================================= test session starts ========================================================
platform linux -- Python 3.8.5, pytest-6.2.2, py-1.10.0, pluggy-0.13.1
rootdir: /vagrant/wazuh-qa/tests/integration, configfile: pytest.ini
plugins: html-2.0.1, testinfra-5.0.0, metadata-1.11.0
collected 1 item

test_files/test_audit/test_remove_rule_five_times.py .                                                                       [100%]

======================================================== 1 passed in 4.34s =========================================================
```

## Code documentation

::: tests.integration.test_fim.test_files.test_audit.test_remove_rule_five_times
