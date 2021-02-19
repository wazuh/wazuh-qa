# Test audit
This test file has several tests:
- `test_audit_health_check`: Checks the behavior of the FIM audit health check.
- `test_added_rules`: Checks if FIM adds the rules for monitored directories using whodata.
- `test_readded_rules`: Checks that FIM is able to re-add the rule of a directory if it's removed.
- `test_readded_rules_on_restart`: Check if FIM is able to add the audit rules when auditd is restarted.
- `test_move_rules_to_realtime`: Checks that FIM moves the monitored directories using `whodata` to realtime when auditd is stopped.
- `test_audit_key`: Checks that the `audit_key` functionality works.
- `test_restart_audit`: Checks that the `<restart_audit>` functionality works.
## General info

| Tier | Platforms | Time spent| Test file |
|:--:|:--:|:--:|:--:|
| 1 | Linux | 00:01:20 | [test_audit.py](../../../../../../tests/integration/test_fim/test_files/test_audit/test_audit.py)|

## Test logic

### test_audit_health_check
- The test will monitor a folder using `whodata`
- It will check that the health check passed.

### test_added_rules
- The test will monitor several folders using `whodata`
- Once FIM starts, the test will check if the a rule for every monitored directory is added

### test_readded_rules
- The test will monitor a folder using `whodata`.
- Once FIM starts, the test will remove the audit rule (using `auditctl`) and will wait until the manipulation event is triggered.
- Finally, the test will check that the audit rule is added again.

### test_readded_rules_on_restart
- The test will monitor a folder using `whodata`.
- Once FIM starts, the test will restart auditd and it will wait until auditd has started.
- After auditd is running, he test will wait for the `connect` and the `load rule` events.

### test_move_rules_realtime
- The test will monitor several folders using `whodata`
- Once FIM starts, the test will stop the auditd service.
- Then it will wait until the monitored directories using `whodata` are monitored with `realtime`

### test_audit_key
- The test will manually add a rule for a monitored path using a custom audit key.
- After FIM starts, the test will check that the events that are generated with the custom key are processed.

### test_restart_audit
- The test removes the audit plugin file.
- Then it will check the audit creation time.
## Checks

- [x] Checks that FIM audit health check works.
- [X] Checks that FIM adds audit rules for monitored directories.
- [X] Checks that FIM is able to re-add audit rules.
- [X] Checks that FIM moves the directories to realtime when whodata is not available.
- [X] Checks the FIM behavior of the `audit_key` and `restart_audit` options.


## Execution result

```
python3 -m pytest test_files/test_audit/test_audit.py
======================================================= test session starts ========================================================
platform linux -- Python 3.8.5, pytest-6.2.2, py-1.10.0, pluggy-0.13.1
rootdir: /vagrant/wazuh-qa/tests/integration, configfile: pytest.ini
plugins: html-2.0.1, testinfra-5.0.0, metadata-1.11.0
collected 24 items

test_files/test_audit/test_audit.py .....sssssssss.ssssssss.                                                                 [100%]

============================================= 7 passed, 17 skipped in 80.86s (0:01:20) =============================================

```

## Code documentation

<!-- ::: tests.integration.test_fim.test_files.test_audit.test_audit -->
