# Test audit after initial scan
This test file has two tests:

The first one, called `test_remove_and_read_folder` checks that FIM monitors a folder if it's removed and created.
The second one, restarts `auditd` and checks if `whodata` works.

## General info

| Tier | Platforms | Time spent| Test file |
|:--:|:--:|:--:|:--:|
| 1 | Linux | 00:01:33 | [test_audit_after_initial_scan.py](../../../../../../tests/integration/test_fim/test_files/test_audit/test_audit_after_initial_scan.py)|

## Test logic

### test_remove_and_read_folder
- The test will monitor a folder using `whodata`
- Once FIM starts, the test will remove the folder and checks if the audit rule associated to that folder has been removed.
- Finally, it creates again the same folder and checks that the audit rule is added.

### test_reconnect_to_audit
- The test will monitor a folder using `whodata`
- Then it will restart the `auditd` daemon.
- Finally, the test waits until FIM is able connect to audit.

## Checks

- [x] Checks that FIM can recover from loosing it's connection to audit.
- [x] Checks that FIM is able to monitor the folders using whodata after they are removed and created again.

## Execution result

```
python3 -m pytest test_files/test_audit/test_audit_after_initial_scan.py
======================================================= test session starts ========================================================
platform linux -- Python 3.8.5, pytest-6.2.2, py-1.10.0, pluggy-0.13.1
rootdir: /vagrant/wazuh-qa/tests/integration, configfile: pytest.ini
plugins: html-2.0.1, testinfra-5.0.0, metadata-1.11.0
collected 4 items

test_files/test_audit/test_audit_after_initial_scan.py ....                                                                  [100%]

=================================================== 4 passed in 93.54s (0:01:33) ===================================================
```

## Code documentation

<!-- ::: tests.integration.test_fim.test_files.test_audit.test_audit_after_initial_scan -->
