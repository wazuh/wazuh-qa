# Test basic usage db inode check

The test check for false positives due to possible inconsistencies with inodes in the database.

## General info

| Tier | Platforms | Time spent| Test file |
|:--:|:--:|:--:|:--:|
| 0 | Linux | 00:00:37 | [test_basic_usage_db_inode_check.py](../../../../../../tests/integration/test_fim/test_files/test_basic_usage/test_basic_usage_db_inode_check.)|

## Test logic

- The test will monitor a folder using `scheduled`.
- The test will create ten files with some content and wait for scan.
- Then, remove files, and create again (adding one more at the beginning, or deleting it) with different inodes.
- Time travel to the next scan and check if there are any unexpected events in the log.

## Checks

- [x] Check that the FIM database does not become inconsistent due to the change of inodes, whether or not `check_mtime` and `check_inode` are enabled.

## Execution result

```
python3 -m pytest --html=/vagrant/report.html tests/integration/test_fim/test_files/test_basic_usage/test_basic_usage_db_inode_check.py
======================================= test session starts ========================================
platform linux -- Python 3.8.5, pytest-6.2.1, py-1.10.0, pluggy-0.13.1
rootdir: /home/vagrant/wazuh-qa/tests/integration, configfile: pytest.ini
plugins: html-2.0.1, testinfra-5.0.0, metadata-1.11.0
collected 4 items

tests/integration/test_fim/test_files/test_basic_usage/test_basic_usage_db_inode_check.py .. [ 50%]
..                                                                                           [100%]

------------------------- generated html file: file:///vagrant/report.html -------------------------
======================================== 4 passed in 37.66s ========================================

```

## Code documentation

::: tests.integration.test_fim.test_files.test_basic_usage.test_basic_usage_db_inode_check
