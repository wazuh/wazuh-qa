# Test change target

Check that FIM correctly monitors folders that replaced monitored symbolic links when the option `follow_symbolic_link` is enabled.
## General info

| Tier | Platforms | Time spent| Test file |
|:--:|:--:|:--:|:--:|
| 1 | Linux/UNIX | 00:00:20 | [test_symlink_to_dir_between_scans.py](../../../../../../tests/integration/test_fim/test_files/test_follow_symbolic_link/ test_symlink_dir_inside_monitored_dir.py)|

## Test logic

- The test will create a directory with some files and a symbolic link.
- Then, it will remove the link and will create a directory with the same path.
- Then, it will wait until the next scheduled scan and will check that new files triggers events.
## Checks

- [x] FIM monitors directories that have replaced symbolic links.

## Execution result

```
python3 -m pytest test_files/test_follow_symbolic_link/test_symlink_to_dir_between_scans.py
=============================================== test session starts ================================================
platform linux -- Python 3.8.5, pytest-6.2.2, py-1.10.0, pluggy-0.13.1
rootdir: /vagrant/wazuh-qa/tests/integration, configfile: pytest.ini
plugins: html-2.0.1, testinfra-5.0.0, metadata-1.11.0
collected 1 item

test_files/test_follow_symbolic_link/test_symlink_to_dir_between_scans.py .                                  [100%]

================================================ 1 passed in 22.95s ================================================
```

## Code documentation

<!-- ::: tests.integration.test_fim.test_files.test_follow_symbolic_link.test_symlink_to_dir_between_scans -->
