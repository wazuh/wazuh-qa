# Test change target
Check if FIM stops detecting events when deleting the target of a monitored symbolic link.

## General info

| Tier | Platforms | Time spent| Test file |
|:--:|:--:|:--:|:--:|
| 1 | Linux/UNIX | 00:03:00 | [test_delete_target.py](../../../../../../tests/integration/test_fim/test_files/test_follow_symbolic_link/test_delete_target.py)|

## Test logic

- The test will monitor a symbolic link pointing to a file/directory.
- Once FIM starts, it will create and expect events inside the pointed folder.
- After the events are processed, the test will remove the link's target, wait until the links are reloaded. Before the next link reload, the test will create again the file/directory and will generate events inside the target that the link was pointing to and check that no alerts are triggered.
- Then, the test will wait until the links are reloaded, it will generate and checks the events with the uploaded link.
## Checks

- [x] FIM stops monitoring the link's target if the target was removed.
- [x] FIM will monitor again the target directory/file if the target is restored.

## Execution result

```
python3 -m pytest test_files/test_follow_symbolic_link/test_delete_target.py
===================================================== test session starts ======================================================
platform linux -- Python 3.8.5, pytest-6.2.2, py-1.10.0, pluggy-0.13.1
rootdir: /vagrant/wazuh-qa/tests/integration, configfile: pytest.ini
plugins: html-2.0.1, testinfra-5.0.0, metadata-1.11.0
collected 12 items

test_files/test_follow_symbolic_link/test_delete_target.py .ss..ss..ss.                                                  [100%]

=========================================== 6 passed, 6 skipped in 357.27s (0:05:57) ===========================================
```

## Code documentation

<!-- ::: tests.integration.test_fim.test_files.test_follow_symbolic_link.test_delete_target -->
