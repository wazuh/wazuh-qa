# Test change target

Checks if FIM updates the symbolic link's target properly.

## General info

| Tier | Platforms | Time spent| Test file |
|:--:|:--:|:--:|:--:|
| 1 | Linux/UNIX | 00:03:00 | [test_change_target.py](../../../../../../tests/integration/test_fim/test_files/test_follow_symbolic_link/test_change_target.py)|

## Test logic

- The test will monitor a symbolic link pointing to a file/directory.
- Once FIM starts, it will create and expect events inside the pointed folder and will create files inside the new target making sure that it won't generate any alerts.
- After the events are processed, the test will change the target of the link to another folder, it will wait until the thread that checks the symbolic links updates the link's target.
- Then, the test checks the new file is being monitored and the old one is not.

## Checks

- [x] The rule is removed.
- [x] The events are triggered for all the link's targets

## Execution result

```
python3 -m pytest test_files/test_follow_symbolic_link/test_change_target.py
===================================================== test session starts ======================================================
platform linux -- Python 3.8.5, pytest-6.2.2, py-1.10.0, pluggy-0.13.1
rootdir: /vagrant/wazuh-qa/tests/integration, configfile: pytest.ini
plugins: html-2.0.1, testinfra-5.0.0, metadata-1.11.0
collected 12 items

test_files/test_follow_symbolic_link/test_change_target.py .ss..ss..ss.                                                  [100%]

=========================================== 6 passed, 6 skipped in 176.83s (0:02:56) ===========================================

```

## Code documentation

::: tests.integration.test_fim.test_files.test_follow_symbolic_link.test_change_target
