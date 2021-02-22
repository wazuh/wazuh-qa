# Test audit no dir
This test checks that FIM doesn't add audit rules for non-existing directories.

## General info

| Tier | Platforms | Time spent| Test file |
|:--:|:--:|:--:|:--:|
| 1 | Linux | 00:00:32 | [test_audit_no_dir.py](../../../../../../tests/integration/test_fim/test_files/test_audit/test_audit_no_dir.py)|

## Test logic

### test_remove_and_read_folder
- The test will monitor a non-existing folder using `whodata`
- Once FIM starts, the test will check that the audit rule is not added.
- Then, it will create the folder and wait until the rule is added again.

## Checks

- [x] Checks that FIM doesn't add rules for non-existing directories.
- [x] Checks that FIM is able to monitor a folder after it's creation.
## Execution result

```
python3 -m pytest test_files/test_audit/test_audit_no_dir.py
======================================================= test session starts ========================================================
platform linux -- Python 3.8.5, pytest-6.2.2, py-1.10.0, pluggy-0.13.1
rootdir: /vagrant/wazuh-qa/tests/integration, configfile: pytest.ini
plugins: html-2.0.1, testinfra-5.0.0, metadata-1.11.0
collected 1 item

test_files/test_audit/test_audit_no_dir.py .                                                                                 [100%]

======================================================== 1 passed in 31.96s ========================================================
```

## Code documentation

::: tests.integration.test_fim.test_files.test_audit.test_audit_no_dir
