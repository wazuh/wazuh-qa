# Test change target

Check if FIM scans a directory silently when a link is changed, preventing events from triggering until it has finished.
## General info

| Tier | Platforms | Time spent| Test file |
|:--:|:--:|:--:|:--:|
| 1 | Linux/UNIX | 00:02:00 | [test_symlink_and_dir.py](../../../../../../tests/integration/test_fim/test_files/test_follow_symbolic_link/test_symlink_and_dir.py)|

## Test logic

- The test will create a link to a file/directory.
- Then, it will change the target to non empty directory, checking that no events are triggered for the files already in the directory.
- Finally, the test generates events and checks that alerts are triggered.
## Checks

- [x] FIM doesn't trigger alerts for already existing files when a link is changed to a non empty directory.

## Execution result

```
python3 -m pytest test_files/test_follow_symbolic_link/test_symlink_and_dir.py
=============================================== test session starts ================================================
platform linux -- Python 3.8.5, pytest-6.2.2, py-1.10.0, pluggy-0.13.1
rootdir: /vagrant/wazuh-qa/tests/integration, configfile: pytest.ini
plugins: html-2.0.1, testinfra-5.0.0, metadata-1.11.0
collected 3 items

test_files/test_follow_symbolic_link/test_symlink_and_dir.py ...                                             [100%]

=========================================== 3 passed in 95.67s (0:01:35) ===========================================
```

## Code documentation

<!-- ::: tests.integration.test_fim.test_files.test_follow_symbolic_link.test_symlink_and_dir -->
