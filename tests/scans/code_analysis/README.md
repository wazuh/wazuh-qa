
# Code Analysis

The `code_analysis` directory contains Python tests used to verify possible vulnerabilities in the Wazuh Python code.

## Test Python Flaws

### Description

`test_python_flaws.py` is a Pytest test used to look for new possible vulnerabilities in directories containing Python code.

The test uses `Bandit` to look for these possible flaws.

In order to find new vulnerabilities, the test compares the Bandit output with vulnerabilities that we consider false positives or vulnerabilities to fix and that we save in three JSON files. By default, the directories we are checking are the `framework/`, `api/` and `wodles/` directories of the **Wazuh** repository.

This test is located at `wazuh-qa/tests/scans/code_analysis`.
In this directory, we can find the test itself, called `test_python_flaws.py`, this `README.md`, a pytest configuration file (`conftest.py`); and a folder called `known_flaws`.

- `known_flaws`: contains three JSON files. Each file contains a dictionary with two keys: false_positives and to_fix. The values are a list of vulnerabilities considered false positives and a list of vulnerabilities we must fix (with issues), respectively. 
These files must be edited after analyzing new vulnerabilities when passing the test.

- `conftest.py`: pytest configuration file. It adds the possibility to use specific parameters when passing the test.

- `test_python_flaws.py`: the test itself. This test will be passed using the same Python virtual environment used in the Wazuh framework and API unittests. 
If the test fails, a new JSON file will be created in `wazuh-qa/tests/scans/code_analysis` showing information about the possible new vulnerabilities found.

### Usage

The workaround for this test will be the following:

- Pass the test.

- If the test passes, no actions are needed, everything is correct.

- If the test fails, new code vulnerabilities will be found in `wazuh-qa/tests/scans/code_analysis/new_flaws_{module}.json`. 
  - We analyze the new vulnerabilities found in the module and report them in GitHub issues.
  - We move the vulnerabilities to the `to_fix` key of the known flaws JSON file.
  - If the new vulnerability is considered a false positive, we add it to the `false_positives` list of the dictionary in its respective `known_flaws` JSON file.
  - If the new vulnerability is a real vulnerability, we solve the problem reported and remove the flaw from the known flaws file.

The test also updates the known_flaws files automatically. If we have a look to a known_flaws file, we will see that each flaw dictionary contains information like the line number or range. This information si the one updated by the test. The test also removes flaws from the known_flaws file if they don't appear in the Bandit output. 

#### Parameters

As said in the description, the test uses `Bandit` to look for possible Python flaws. By default, the tests checks the framework, wodles and api directories in the Wazuh repository, in its master branch. 

These directories, repository and branch can be passed to the test as parameters so it is possible to run the test in any directory containing Python code inside the Wazuh organization.

Apart from this parameters, there are more that can be used to customize the test functionality. Note that the test will fail if we check different directories and/or repository as we don't have known_flaws files for non-default directories.

- **--repo**: set the repository used. Default: `wazuh`
- **--branch**: set the repository branch. Default: `master`
- **--check_directories**: set the directories to check, this must be a string with the directory name. 
If more than one is indicated, they must be separated with comma. Default: `framework/,api/,wodles/`.
- **--exclude_directories**: set the directories to exclude, this must be a string with the directory name.
If more than one is indicated, they must be separated with comma. Default: `test/,tests/`.
- **--confidence**: set the minimum value of confidence of the Bandit scan. 
This value must be 'UNDEFINED', 'LOW', 'MEDIUM' or 'HIGH'. Default: `MEDIUM`
- **--severity**: set the minimum value of severity of the Bandit scan.
This value must be 'UNDEFINED', 'LOW', 'MEDIUM' or 'HIGH'. Default: `LOW`


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
