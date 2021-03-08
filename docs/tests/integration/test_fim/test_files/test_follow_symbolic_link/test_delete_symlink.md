# Test change target
Check if FIM stops detecting events when deleting the monitored symbolic link.

## General info

| Tier | Platforms | Time spent| Test file |
|:--:|:--:|:--:|:--:|
| 1 | Linux/UNIX | 00:05:00 | [test_delete_symlink.py](../../../../../../tests/integration/test_fim/test_files/test_follow_symbolic_link/test_delete_symlink.py)|

## Test logic

- The test will monitor a symbolic link pointing to a file/directory.
- Once FIM starts, it will create and expect events inside the pointed folder.
- After the events are processed, the test will remove the symbolic link, wait until the links are reloaded and will create files inside the target that the link was pointing to and check that no alerts are triggered.
- Then, the test will restore the link, it will wait until the link is updated and it will generate events inside the target folder and check that the alerts are triggered.
## Checks

- [x] FIM stops monitoring the link's target if the link was removed.
- [x] FIM will monitor again the target directory/file if the link is restored.

## Execution result

```
python3 -m pytest test_files/test_follow_symbolic_link/test_delete_
test_delete_symlink.py  test_delete_target.py
root@ubuntu1:/vagrant/wazuh-qa/tests/integration/test_fim# python3 -m pytest test_files/test_follow_symbolic_link/test_delete_symlink.py
===================================================== test session starts ======================================================
platform linux -- Python 3.8.5, pytest-6.2.2, py-1.10.0, pluggy-0.13.1
rootdir: /vagrant/wazuh-qa/tests/integration, configfile: pytest.ini
plugins: html-2.0.1, testinfra-5.0.0, metadata-1.11.0
collected 12 items

test_files/test_follow_symbolic_link/test_delete_symlink.py .ss..ss..ss.                                                 [100%]

=========================================== 6 passed, 6 skipped in 296.78s (0:04:56) ===========================================


```

## Code documentation

<!-- ::: tests.integration.test_fim.test_files.test_follow_symbolic_link.test_delete_symlink -->
