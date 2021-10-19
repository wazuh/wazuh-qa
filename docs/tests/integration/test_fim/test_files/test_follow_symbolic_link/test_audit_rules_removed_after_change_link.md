# Test audit rules removed after change link

This test checks that FIM removes automatically the audit rule of the target of a monitored symbolic link  when the link's target is replaced.
## General info

| Tier | Platforms | Time spent| Test file |
|:--:|:--:|:--:|:--:|
| 1 | Linux/UNIX | 00:00:33 | [test_audit_rules_removed_after_change_link.py](../../../../../../tests/integration/test_fim/test_files/test_follow_symbolic_link/test_audit_rules_removed_after_change_link.py)|

## Test logic


- The test will monitor a symbolic link pointing to a directory using `whodata`.
- Once FIM starts, it will create and expect events inside the pointed folder.
- After the events are processed, the test will change the target of the link to another  folder, it will wait until the thread that checks the symbolic links updates the link's target.
- Finally, it will generate some events inside the new target and it will check that the audit rule of the previous target folder has been removed (by using `auditctl -l`).

## Checks

- [x] The rule is removed.
- [x] The events are triggered for all the link's targets

## Execution result

```
 python3 -m pytest test_files/test_follow_symbolic_link/test_audit_rules_removed_after_change_link.py
===================================================== test session starts ======================================================
platform linux -- Python 3.8.5, pytest-6.2.2, py-1.10.0, pluggy-0.13.1
rootdir: /vagrant/wazuh-qa/tests/integration, configfile: pytest.ini
plugins: html-2.0.1, testinfra-5.0.0, metadata-1.11.0
collected 1 item

test_files/test_follow_symbolic_link/test_audit_rules_removed_after_change_link.py .                                     [100%]

====================================================== 1 passed in 33.48s ======================================================
```

## Code documentation

<!-- ::: tests.integration.test_fim.test_files.test_follow_symbolic_link.test_audit_rules_removed_after_change_link -->
