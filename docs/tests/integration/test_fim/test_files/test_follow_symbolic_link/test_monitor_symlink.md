# Test change target
Checks the behavior when monitoring a link that points to a file or a directory.

## General info

| Tier | Platforms | Time spent| Test file |
|:--:|:--:|:--:|:--:|
| 1 | Linux/UNIX | 00:02:00 | [test_monitor_symlink.py](../../../../../../tests/integration/test_fim/test_files/test_follow_symbolic_link/test_monitor_symlink.py)|

## Test logic

- The test will monitor a symbolic link pointing to a file/directory.
- Once FIM starts, if the link is a folder, creates a file and checks the expect added event.
- Then, it will modify and expect modified event.
- Finally, the test will remove the link's target and check the delete event.
## Checks

- [x] FIM monitors the target of the link.

## Execution result

```
python3 -m pytest test_files/test_follow_symbolic_link/test_monitor_symlink.py
===================================================== test session starts ======================================================
platform linux -- Python 3.8.5, pytest-6.2.2, py-1.10.0, pluggy-0.13.1
rootdir: /vagrant/wazuh-qa/tests/integration, configfile: pytest.ini
plugins: html-2.0.1, testinfra-5.0.0, metadata-1.11.0
collected 12 items

test_files/test_follow_symbolic_link/test_monitor_symlink.py .ss..ss..ss.                                                [100%]

================================================ 6 passed, 6 skipped in 27.04s =================================================
root@ubuntu1:/vagrant/wazuh-qa/tests/integration/test_fim#
```

## Code documentation

<!-- ::: tests.integration.test_fim.test_files.test_follow_symbolic_link.test_monitor_symlink -->
