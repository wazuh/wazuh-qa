# Code Analysis

The `code_analysis` directory contains Python tests to verify potential vulnerabilities in the Wazuh Python code.

## Description

`test_python_flaws.py` is a Pytest test used to look for new possible vulnerabilities in directories containing Python code. It uses [Bandit](https://github.com/PyCQA/bandit) to search for these potential flaws.

The test checks the `framework/`, `api/` and `wodles/` directories of the [Wazuh](https://github.com/wazuh/wazuh) repository by default, comparing the *Bandit* output with the vulnerabilities identified as false positives or vulnerabilities to fix. It saves the results in three JSON files (one JSON file for each module).

The contents of this directory are:
- `known_flaws`: The directory contains three JSON files, one for each module (`api`, `framework` and `wodles`). Each file has a dictionary with two keys: **false_positives** and **to_fix**. These values are the list of vulnerabilities considered false positives and the list of vulnerabilities you must fix (with issues), respectively. After running the test and analyzing the new vulnerabilities, you must edit these files.
- `conftest.py`: The Pytest configuration file. It adds the possibility to use specific parameters when running the test.
- `test_python_flaws.py`: The test itself. You should run this test using the same Python virtual environment used in the Wazuh framework and API unit tests. If the test fails, a new JSON file will be created inside this directory, showing information about the possible new vulnerabilities found.

## Usage

- Run the test: `pytest tests/scans/code_analysis/test_python_flaws.py`
- If the test passes without failures, everything is correct, and no action is needed.
- If the test fails, `wazuh-qa/tests/scans/code_analysis/new_flaws_{module}.json` file will report the new code vulnerabilities found.
You should analyze the new vulnerabilities found in the module and report them in GitHub issues.

If you need to fix a new vulnerability, add it to the **to_fix** key module's JSON file entry found in the **known_flaws** directory. 
If the new vulnerability is a false positive, add it to the **false_positives** key module's JSON file entry found in the **known_flaws** directory. 

The test updates the files inside **known_flaws** automatically with information like the line number or range of the flaws in the **to_fix** dictionary. The test also removes flaws from the **known_flaws** files if Bandit did not report them.

## Parameters

You can set the directories, repository, and branch parameters to test any directory containing Python code inside the Wazuh organization.
You can also use more parameters to customize the test functionality. The test will only succeed if you check different directories and repositories, as we don't have **known_flaws** files for non-default directories.

> By default, the test checks the `framework`, `wodles` and `api` directories in the [wazuh/wazuh](https://github.com/wazuh/wazuh) repository's master branch.

| Parameter             | Description                                           | Default Value     |
|-----------------------|-------------------------------------------------------|-------------------|
| `--repo`              | The repository to test.                               | `wazuh`           |
| `--reference`         | The repository branch.                                | `master`          |
| `--check_directories` | The directories to check (comma-separated).           | `framework/,api/,wodles/` |
| `--exclude_directories`| The directories to exclude (comma-separated).        | `test/,tests/`    |
| `--confidence`        | Minimum confidence level for Bandit scan.             | `MEDIUM`           |
| `--severity`          | Minimum severity level for Bandit scan.               | `LOW`             |

> The values accepted by the flags `--confidence` and `--security` are `UNDEFINED`, `LOW`, `MEDIUM` or `HIGH`.

#### Example

<details>

<summary>test_output</summary>

```
pytest tests/scans/code_analysis/test_python_flaws.py
============================= test session starts ==============================
platform linux -- Python 3.9.2, pytest-6.2.3, py-1.10.0, pluggy-0.13.1
rootdir: /home/manuel/git/wazuh-qa
plugins: html-3.1.1, metadata-1.11.0, cov-2.12.0, testinfra-5.0.0, asyncio-0.14.0
collected 1 item

tests/scans/code_analysis/test_python_flaws.py F                         [100%]

=================================== FAILURES ===================================
__________________________ test_check_security_flaws ___________________________

clone_wazuh_repository = '/tmp/tmpk9uc0l2g'
get_test_parameters = {'directories_to_check': ['framework/', 'api/', 'wodles/'], 'directories_to_exclude': 'tests/,test/', 'min_confidence_level': 'MEDIUM', 'min_severity_level': 'LOW', ...}

    def test_check_security_flaws(clone_wazuh_repository, get_test_parameters):
        """Test whether the directory to check has python files with possible vulnerabilities or not.

        The test passes if there are no new vulnerabilities. The test fails in other case and generates a report.

        In case there is at least one vulnerability, a json file will be generated with the report. If we consider this
        result or results are false positives, we will move the json object containing each specific result to the
        `known_flaws/known_flaws_{framework|api|wodles}.json` file.

        Args:
            clone_wazuh_repository (fixture): Pytest fixture returning the path of the temporary directory path the
                repository cloned. This directory is removed at the end of the pytest session.
            get_test_parameters (fixture): Pytest fixture returning the a dictionary with all the test parameters.
                These parameters are the directories to check, directories to exclude, the minimum confidence level, the
                minimum severity level and the repository name.
        """
        # Wazuh is cloned from GitHub using the clone_wazuh_repository fixture
        assert clone_wazuh_repository, "Error while cloning the Wazuh repository from GitHub, " \
                                       "please check the Wazuh branch set in the parameter."
        # Change to the cloned Wazuh repository directory
        os.chdir(clone_wazuh_repository)

        directories_to_check = get_test_parameters['directories_to_check']
        bandit_output_list = \
            run_bandit_multiple_directories(directories_to_check,
                                            get_test_parameters['directories_to_exclude'],
                                            get_test_parameters['min_severity_level'],
                                            get_test_parameters['min_confidence_level'])

        flaws_already_found = {}
        for bandit_output, directory in zip(bandit_output_list, directories_to_check):
            assert not bandit_output['errors'], \
                f"\nBandit returned errors when trying to get possible vulnerabilities in the directory " \
                f"{directory}:\n{bandit_output['errors']}"

            bandit_result = bandit_output['results']

            known_flaws = update_known_flaws_in_file(known_flaws_directory=KNOWN_FLAWS_DIRECTORY,
                                                     directory=directory,
                                                     is_default_check_dir=
                                                     directory.replace('/', '') in
                                                     DEFAULT_DIRECTORIES_TO_CHECK.replace('/', '').split(','),
                                                     bandit_results=bandit_result)

            flaws_already_found = get_new_flaws(bandit_results=bandit_result,
                                                known_flaws=known_flaws,
                                                directory=directory,
                                                flaws_already_found=flaws_already_found,
                                                new_flaws_output_dir=TEST_PYTHON_CODE_PATH)

>       assert not any(
            flaws_already_found.get(directory, None) for directory in directories_to_check), \
            f"\nThe following possible vulnerabilities were found: {json.dumps(flaws_already_found, indent=4, sort_keys=True)}"
E       AssertionError:
E         The following possible vulnerabilities were found: {
E             "wodles/": "Vulnerabilities found in files: wodles/utils.py, check them in /home/manuel/git/wazuh-qa/tests/scans/code_analysis/new_flaws_wodles.json"
E         }
E       assert not True
E        +  where True = any(<generator object test_check_security_flaws.<locals>.<genexpr> at 0x7fecf3a6ca50>)

/home/manuel/git/wazuh-qa/tests/scans/code_analysis/test_python_flaws.py:64: AssertionError
=============================== warnings summary ===============================
tests/scans/code_analysis/test_python_flaws.py::test_check_security_flaws
  invalid escape sequence \g

tests/scans/code_analysis/test_python_flaws.py::test_check_security_flaws
  invalid escape sequence \S

tests/scans/code_analysis/test_python_flaws.py::test_check_security_flaws
  invalid escape sequence \s

-- Docs: https://docs.pytest.org/en/stable/warnings.html
=========================== short test summary info ============================
FAILED tests/scans/code_analysis/test_python_flaws.py::test_check_security_flaws
======================== 1 failed, 3 warnings in 28.98s ========================
```

</details>


The vulnerabilities detected are in the following dictionary:

<details>

<summary>vulnerabilities</summary>

```
{
    "new_flaws": [
        {
            "code": " import os\n import subprocess\n from functools import lru_cache\n",
            "filename": "wodles/utils.py",
            "issue_confidence": "HIGH",
            "issue_severity": "LOW",
            "issue_text": "Consider possible security implications associated with subprocess module.",
            "line_number": 6,
            "line_range": [
                6
            ],
            "more_info": "https://bandit.readthedocs.io/en/latest/blacklists/blacklist_imports.html#b404-import-subprocess",
            "test_id": "B404",
            "test_name": "blacklist"
        },
        {
            "code": "     try:\n         proc = subprocess.Popen([wazuh_control, option], stdout=subprocess.PIPE)\n         (stdout, stderr) = proc.communicate()\n",
            "filename": "wodles/utils.py",
            "issue_confidence": "HIGH",
            "issue_severity": "LOW",
            "issue_text": "subprocess call - check for execution of untrusted input.",
            "line_number": 44,
            "line_range": [
                44
            ],
            "more_info": "https://bandit.readthedocs.io/en/latest/plugins/b603_subprocess_without_shell_equals_true.html",
            "test_id": "B603",
            "test_name": "subprocess_without_shell_equals_true"
        },
        {
            "code": "         return stdout.decode()\n     except Exception:\n         pass\n \n",
            "filename": "wodles/utils.py",
            "issue_confidence": "HIGH",
            "issue_severity": "LOW",
            "issue_text": "Try, Except, Pass detected.",
            "line_number": 47,
            "line_range": [
                47,
                48
            ],
            "more_info": "https://bandit.readthedocs.io/en/latest/plugins/b110_try_except_pass.html",
            "test_id": "B110",
            "test_name": "try_except_pass"
        }
    ]
}
```

</details>

After reporting the possible flaws in issues, we move them to the `to_fix` key of `known_flaws/known_flaws_api.json`.

When solving the issue, we will remove the flaw or move it to `false_positives`.

After this, if we pass the test again, it will pass.

```
pytest tests/security/test_python_code/test_python_flaws.py
================================================================= test session starts ==================================================================
platform linux -- Python 3.9.2, pytest-6.2.3, py-1.10.0, pluggy-0.13.1
rootdir: /home/manuel/git/wazuh-qa
plugins: html-3.1.1, metadata-1.11.0, cov-2.12.0, testinfra-5.0.0, asyncio-0.14.0
collected 1 item

tests/security/test_python_code/test_python_flaws.py .                                                                                           [100%]

=================================================================== warnings summary ===================================================================
tests/security/test_python_code/test_python_flaws.py::test_check_security_flaws
  invalid escape sequence \g

tests/security/test_python_code/test_python_flaws.py::test_check_security_flaws
  invalid escape sequence \S

tests/security/test_python_code/test_python_flaws.py::test_check_security_flaws
  invalid escape sequence \s

-- Docs: https://docs.pytest.org/en/stable/warnings.html
====================================================== 1 passed, 3 warnings in 341.31s (0:05:41) =======================================================
```
