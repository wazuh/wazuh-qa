
# Integration tests structure

Our newest integration tests are located in `wazuh-qa/tests/integration/`. They are organized by capabilities:

- _test_analysisd_
- _test_api_
- _test_cluster_
- _test_fim_
- _test_gcloud_
- _test_mitre_
- _test_sca_
- _test_vulnerability_detector_
- _test_wazuh_db_

Every group will have the following structure:

```bash
├── test_<capability>
│   ├── conftest.py (optional)
│   ├── test_<functionality>
│   │   ├── data
│   │   │   ├── <wazuh_conf>.yaml
│   │   │   └── <wazuh_conf>.yaml
│   │   ├── test_<module>.py
│   │   ├── test_<module>.py
│   │   └── test_<module>.py
│   ├── test_<functionality>
│   │   ├── data
│   │   │   └── <wazuh_conf>.yaml
│   │   ├── test_<module>.py
│   │   ├── test_<module>.py
│   │   ├── <auxiliary_module>.py (optional)
└── └── └── <script> (optional)
```

FIM test structure example:

```bash
├── test_fim
│   ├── conftest.py
.
.
.
│   ├── test_basic_usage
│   │   ├── data
│   │   │   ├── wazuh_conf_disabled.yaml
│   │   │   └── wazuh_conf.yaml
│   │   ├── test_basic_disabled.py
│   │   ├── test_basic_usage_baseline_generation.py
│   │   ├── test_basic_usage_changes.py
│   │   ├── test_basic_usage_create_rt_wd.py
│   │   ├── test_basic_usage_create_scheduled.py
│   │   ├── test_basic_usage_delete_folder.py
│   │   ├── test_basic_usage_entries_match_path_count.py
│   │   ├── test_basic_usage_move_dir.py
│   │   ├── test_basic_usage_move_file.py
│   │   ├── test_basic_usage_rename.py
│   │   └── test_basic_usage_starting_agent.py
.
.
.
│   ├── test_skip
│   │   ├── data
│   │   │   ├── configure_nfs.sh
│   │   │   ├── proc.py
│   │   │   ├── remove_nfs.sh
│   │   │   └── wazuh_conf.yaml
│   │   └── test_skip.py
│   ├── test_windows_audit_interval
│   │   ├── data
│   │   │   └── wazuh_conf.yaml
│   │   ├── manage_acl.py
│   │   └── test_windows_audit_interval.py
.
.
.
```

#### conftest

Every group could have its own `conftest` if it needed some specific configurations. For reference, please check [pytest](#pytest) section below.

#### data

Folder with the configuration yaml's to create the testing environment. These yaml's have the `ossec.conf` that will be applied to each module.
This is a sample yaml used for `FIM`:

```yaml
---
# sample configuration
- tags:
  - sample_tag
  apply_to_modules:
  - sample_module
  sections:
  - section: syscheck
    elements:
    - disabled:
      value: 'no'
    - directories:
      value: '/sample_directory'
      attributes:
      - check_all: 'yes'
    - nodiff:
      value: '/sample_directory/nodiff_file'
```

- **tags**: Informative tag that could be used to filter out within test functions for the same module.
- **apply_to_modules**: Module/s that will load this configuration.
- **section**: Section that will be modified within `<ossec_config`.
- **elements**: Elements that will be written within the given section.
    - disabled: `<disabled>no</disabled>`
    - directories: `<directories check_all="yes">/sample_directory</directories>`
    - nodiff: `<nodiff>/sample_directory/nodiff_file</nodiff>`

We can use `wildcards` as well to parametrize values or attributes. For example, if we add a new attribute into the previous configuration called `FIM_MODE` and we set this wildcard to `''`, `realtime="yes"` and `whodata="yes"`, it will generate **three** different configurations. One for each _WILDCARD_ value.

#### test_module

This will be our python module with all the needed code to test everything.

### Dependencies

To run them, we need to install all these Python dependencies:

```shell script
pip3 install distro freezegun jq jsonschema paramiko psutil pydevd-pycharm pytest pyyaml==5.3 pandas pytest-html==2.0.1 numpydoc==0.9.2
```

_**NOTE:** `jq` library can only be installed with `pip` on **Linux**_

### Pytest

We use [pytest](https://docs.pytest.org/en/latest/contents.html) to run our integrity tests. Pytest will recursively look for the closest `conftest` to import all the variables and fixtures needed for every test. If something is lacking from the closest one, it will look for the next one (if possible) until reaching the current directory. This means we need to run every test from the following path, where the general _conftest_ is:

```shell script
cd wazuh-qa/tests/integration
```

To run any test, we just need to call `pytest` from `python3` using the following line:

```shell script
python3 -m pytest [options] [file_or_dir] [file_or_dir] [...]
```

**Options:**

- `v`: verbosity level (-v or -vv. Highly recommended to use -vv when tests are failing)
- `s`: shortcut for --capture=no. This will show the output in real time
- `x`: instantly exit after the first error. Very helpful when using a log truncate since it will keep the last failed result
- `m`: only run tests matching given expression (-m MARKEXPR)
- `--tier`: only run tests with given tier (ex. --tier 2)
- `--html`: generates a HTML report for the test results. (ex. --html=report.html)
- `--default-timeout`: overwrites the default timeout (in seconds). This value is used to make a test fail if a condition
is not met before the given time lapse. Some tests make use of this value and other has other fixed timeout that cannot be
modified.

_Use `-h` to see the rest or check its [documentation](https://docs.pytest.org/en/latest/usage.html)._

Also, these integration tests are heavily based on [fixtures](https://docs.pytest.org/en/latest/fixture.html), so please check its documentation for further information.

#### FIM integration tests examples

```shell script
python3 -m pytest -vvx test_fim/test_basic_usage/test_basic_usage_create_scheduled.py

========================================== test session starts ==========================================
platform linux -- Python 3.6.8, pytest-5.3.4, py-1.8.1, pluggy-0.13.1 -- /bin/python3
cachedir: .pytest_cache
rootdir: /vagrant/wazuh-qa/test_wazuh, inifile: pytest.ini
collected 12 items

test_fim/test_basic_usage/test_basic_usage_create_scheduled.py::test_create_file_scheduled[get_configuration0-file-regular-Sample content-checkers0-tags_to_apply0-/testdir1] PASSED [  8%]
test_fim/test_basic_usage/test_basic_usage_create_scheduled.py::test_create_file_scheduled[get_configuration0-file-regular-Sample content-checkers0-tags_to_apply0-/testdir2] PASSED [ 16%]
test_fim/test_basic_usage/test_basic_usage_create_scheduled.py::test_create_file_scheduled[get_configuration0-file2-regular-Sample content-checkers1-tags_to_apply1-/testdir1] PASSED [ 25%]
test_fim/test_basic_usage/test_basic_usage_create_scheduled.py::test_create_file_scheduled[get_configuration0-file2-regular-Sample content-checkers1-tags_to_apply1-/testdir2] PASSED [ 33%]
test_fim/test_basic_usage/test_basic_usage_create_scheduled.py::test_create_file_scheduled[get_configuration0-socketfile-socket--checkers2-tags_to_apply2-/testdir1] PASSED [ 41%]
test_fim/test_basic_usage/test_basic_usage_create_scheduled.py::test_create_file_scheduled[get_configuration0-socketfile-socket--checkers2-tags_to_apply2-/testdir2] PASSED [ 50%]
test_fim/test_basic_usage/test_basic_usage_create_scheduled.py::test_create_file_scheduled[get_configuration0-file3-regular-Sample content-checkers3-tags_to_apply3-/testdir1] PASSED [ 58%]
test_fim/test_basic_usage/test_basic_usage_create_scheduled.py::test_create_file_scheduled[get_configuration0-file3-regular-Sample content-checkers3-tags_to_apply3-/testdir2] PASSED [ 66%]
test_fim/test_basic_usage/test_basic_usage_create_scheduled.py::test_create_file_scheduled[get_configuration0-fifofile-fifo--checkers4-tags_to_apply4-/testdir1] PASSED [ 75%]
test_fim/test_basic_usage/test_basic_usage_create_scheduled.py::test_create_file_scheduled[get_configuration0-fifofile-fifo--checkers4-tags_to_apply4-/testdir2] PASSED [ 83%]
test_fim/test_basic_usage/test_basic_usage_create_scheduled.py::test_create_file_scheduled[get_configuration0-file4-regular--checkers5-tags_to_apply5-/testdir1] PASSED [ 91%]
test_fim/test_basic_usage/test_basic_usage_create_scheduled.py::test_create_file_scheduled[get_configuration0-file4-regular--checkers5-tags_to_apply5-/testdir2] PASSED [100%]

===================================== 12 passed in 60.38s (0:01:00) =====================================

```

```shell script
python3 -m pytest test_fim/test_report_changes/

=============================== test session starts ===============================
platform linux -- Python 3.6.8, pytest-5.3.4, py-1.8.1, pluggy-0.13.1
rootdir: /vagrant/wazuh-qa/test_wazuh, inifile: pytest.ini
collected 12 items

test_fim/test_report_changes/test_report_changes_and_diff.py ......         [ 50%]
test_fim/test_report_changes/test_report_deleted_diff.py ......             [100%]

========================= 12 passed in 212.23s (0:03:32) ==========================
```
