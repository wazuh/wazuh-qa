
# Test Python Code

The `test_python_code` directory contains Python tests used to verify possible vulnerabilities in the Wazuh Python code.

## Test Python Flaws

### Description

`test_python_flaws.py` is a Pytest test used to look for new possible vulnerabilities in directories containing Python code.

The test uses `Bandit` to look for these possible flaws.

In order to find new vulnerabilities, the test compares the Bandit output with vulnerabilities that we consider false positives or vulnerabilities to fix and that we save in three JSON files. By default, the directories we are checking are the `framework/`, `api/` and `wodles/` directories of the **Wazuh** repository.

This test is located at `wazuh-qa/tests/security/test_python_code`.
In this directory, we can find the test itself, called `test_python_flaws.py`, this `README.md`, a pytest configuration file (`conftest.py`); and a folder called `known_flaws`.

- `known_flaws`: contains three JSON files. Each file contains a dictionary with two keys: false_positives and to_fix. The values are a list of vulnerabilities considered false positives and a list of vulnerabilities we must fix (with issues), respectively. 
These files must be edited after analyzing new vulnerabilities when passing the test.

- `conftest.py`: pytest configuration file. It adds the possibility to use specific parameters when passing the test.

- `test_python_flaws.py`: the test itself. This test will be passed using the same Python virtual environment used in the Wazuh framework and API unittests. 
If the test fails, a new JSON file will be created in `wazuh-qa/tests/security/test_python_code` showing information about the possible new vulnerabilities found.

### Usage

The workaround for this test will be the following:

- Pass the test.

- If the test passes, no actions are needed, everything is correct.

- If the test fails, new code vulnerabilities will be found in `wazuh-qa/tests/security/test_python_code/new_flaws_{module}.json`. 
  - We analyze the new vulnerabilities found in the module.
  - If the new vulnerability is considered a false positive, we add it to the `false_positives` list of the dictionary in its respective `known_flaws` JSON file.
  - If the new vulnerability is a real vulnerability, we try to fix it or we add it to the `to_fix` list and create an issue.

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
pytest tests/security/test_python_code/test_python_flaws.py
================================================================= test session starts ==================================================================
platform linux -- Python 3.9.2, pytest-6.2.3, py-1.10.0, pluggy-0.13.1
rootdir: /home/manuel/git/wazuh-qa
plugins: html-3.1.1, metadata-1.11.0, cov-2.12.0, testinfra-5.0.0, asyncio-0.14.0
collected 1 item                                                                                                                                       

tests/security/test_python_code/test_python_flaws.py F                                                                                           [100%]

======================================================================= FAILURES =======================================================================
______________________________________________________________ test_check_security_flaws _______________________________________________________________

clone_wazuh_repository = '/tmp/tmps0xcjyv2'
test_parameters = {'directories_to_check': ['framework/', 'api/', 'wodles/'], 'directories_to_exclude': 'tests/,test/', 'min_confidence_level': 'MEDIUM', 'min_severity_level': 'LOW', ...}

    def test_check_security_flaws(clone_wazuh_repository, test_parameters):
        """Test whether the directory to check has python files with possible vulnerabilities or not.
    
        The test passes if there are no new vulnerabilities. The test fails in other case and generates a report.
    
        In case there is at least one vulnerability, a json file will be generated with the report. If we consider this
        result or results are false positives, we will move the json object containing each specific result to the
        `known_flaws/known_flaws_{framework|api|wodles}.json` file.
    
        Args:
            clone_wazuh_repository (fixture): Pytest fixture returning the path of the temporary directory path the
                repository cloned. This directory is removed at the end of the pytest session.
            test_parameters (fixture): Pytest fixture returning the a dictionary with all the test parameters.
                These parameters are the directories to check, directories to exclude, the minimum confidence level, the
                minimum severity level and the repository name.
        """
        # Wazuh is cloned from GitHub using the clone_wazuh_repository fixture
        assert clone_wazuh_repository, "Error while cloning the Wazuh repository from GitHub, " \
                                       "please check the Wazuh branch set in the parameter."
        # Change to the cloned Wazuh repository directory
        os.chdir(clone_wazuh_repository)
    
        flaws_found = {}
        for directory_to_check in test_parameters['directories_to_check']:
            is_default_check_dir = directory_to_check.replace('/', '') in \
                                   DEFAULT_DIRECTORIES_TO_CHECK.replace('/', '').split(',') and test_parameters[
                                       'repository'] == DEFAULT_REPOSITORY
            # Run Bandit scan
            bandit_output = run_bandit_scan(directory_to_check,
                                            test_parameters['directories_to_exclude'],
                                            test_parameters['min_severity_level'],
                                            test_parameters['min_confidence_level'])
            assert not bandit_output['errors'], \
                f"\nBandit returned errors when trying to get possible vulnerabilities in the directory " \
                f"{directory_to_check}:\n{bandit_output['errors']}"
    
            # We save the results obtained in the report as the rest of information is redundant or not used
            results = bandit_output['results']
    
            # Delete line numbers in code to make it persistent with updates
            for result in results:
                result['code'] = re.sub(r"^\d+", "", result['code'])  # Delete first line number
                result['code'] = re.sub(r"\n\d+", "\n", result['code'], re.M)  # Delete line numbers after newline
    
            # Compare the flaws obtained in results with the known flaws
            if is_default_check_dir:
                try:
                    with open(f"{KNOWN_FLAWS_DIRECTORY}/known_flaws_{directory_to_check.replace('/', '')}.json",
                              mode="r") as f:
                        known_flaws = json.load(f)
                except json.decoder.JSONDecodeError or FileNotFoundError:
                    known_flaws = {'false_positives': [], 'to_fix': []}
            else:
                known_flaws = {'false_positives': [], 'to_fix': []}
    
            # There are security flaws if there are new possible vulnerabilities detected
            # To compare them, we cannot compare the whole dictionaries containing the flaws as the values of keys like
            # line_number and line_range will vary
            # Update known flaws with the ones detected in this Bandit run, remove them if they were fixed
            known_flaws = update_known_flaws(known_flaws, results)
            if is_default_check_dir:
                with open(f"{KNOWN_FLAWS_DIRECTORY}/known_flaws_{directory_to_check.replace('/', '')}.json", mode="w") as f:
                    f.write(json.dumps(known_flaws, indent=4, sort_keys=True))
            else:
                # if the directory to check is not one of the default list, we will create a new known_flaws file outside
                # the directory known_flaws, to avoid overwriting
                with open(f"known_flaws_{directory_to_check.replace('/', '')}.json", mode="w") as f:
                    f.write(json.dumps(known_flaws, indent=4, sort_keys=True))
    
            new_flaws = [flaw for flaw in results if
                         flaw not in known_flaws['to_fix'] and flaw not in known_flaws['false_positives']]
            if new_flaws:
                # Write new flaws in a temporal file to analyze them
                new_flaws_path = os.path.join(TEST_PYTHON_CODE_PATH,
                                              f"new_flaws_{directory_to_check.replace('/', '')}.json")
                with open(new_flaws_path, mode="w+") as f:
                    f.write(json.dumps({'new_flaws': new_flaws}, indent=4, sort_keys=True))
                files_with_flaws = ', '.join(list(dict.fromkeys([res['filename'] for res in new_flaws])))
                flaws_found[directory_to_check] = f"Vulnerabilities found in files: {files_with_flaws}," \
                                                  f" check them in {new_flaws_path}"
    
>       assert not any(flaws_found.get(directory, None) for directory in test_parameters['directories_to_check']), \
            f"\nThe following possible vulnerabilities were found: {json.dumps(flaws_found, indent=4, sort_keys=True)}"
E       AssertionError: 
E         The following possible vulnerabilities were found: {
E             "api/": "Vulnerabilities found in files: api/scripts/wazuh-apid.py, check them in /home/manuel/git/wazuh-qa/tests/security/test_python_code/new_flaws_api.json"
E         }
E       assert not True
E        +  where True = any(<generator object test_check_security_flaws.<locals>.<genexpr> at 0x7f7240a67350>)

/home/manuel/git/wazuh-qa/tests/security/test_python_code/test_python_flaws.py:220: AssertionError
=================================================================== warnings summary ===================================================================
tests/security/test_python_code/test_python_flaws.py::test_check_security_flaws
  invalid escape sequence \g

tests/security/test_python_code/test_python_flaws.py::test_check_security_flaws
  invalid escape sequence \S

tests/security/test_python_code/test_python_flaws.py::test_check_security_flaws
  invalid escape sequence \s

-- Docs: https://docs.pytest.org/en/stable/warnings.html
=============================================================== short test summary info ================================================================
FAILED tests/security/test_python_code/test_python_flaws.py::test_check_security_flaws - AssertionError: 
====================================================== 1 failed, 3 warnings in 223.18s (0:03:43) =======================================================
```

</details>


The vulnerability detected is:

```
{
    "new_flaws": [
        {
            "code": "                                )\n     app.add_api('spec.yaml',\n                 arguments={'title': 'Wazuh API',\n                            'protocol': 'https' if api_conf['https']['enabled'] else 'http',\n                            'host': api_conf['host'],\n                            'port': api_conf['port']\n                            },\n                 strict_validation=True,\n                 validate_responses=False,\n162                 pass_context_arg_name='request',\n163                 options={\"middlewares\": [response_postprocessing, set_user_name, security_middleware, request_logging,\n164                                          set_secure_headers]})\n165 \n",
            "filename": "api/scripts/wazuh-apid.py",
            "issue_confidence": "MEDIUM",
            "issue_severity": "LOW",
            "issue_text": "Possible hardcoded password: 'request'",
            "line_number": 154,
            "line_range": [
                154,
                155,
                156,
                157,
                158,
                159,
                160,
                161,
                162,
                163,
                164
            ],
            "more_info": "https://bandit.readthedocs.io/en/latest/plugins/b106_hardcoded_password_funcarg.html",
            "test_id": "B106",
            "test_name": "hardcoded_password_funcarg"
        }
    ]
}
```

After analyzing the possible flaw, we see it is a false positive, we move it to `known_flaws/known_flaws_api.json`.

<details>

<summary>known_flaws/known_flaws_api.json</summary>

```
{
    "false_positives": [
        {
            "code": " default_api_configuration = {\n     \"host\": \"0.0.0.0\",\n     \"port\": 55000,\n     \"use_only_authd\": False,\n     \"drop_privileges\": True,\n     \"experimental_features\": False,\n     \"max_upload_size\": 10485760,\n     \"intervals\": {\n         \"request_timeout\": 10\n38     },\n39     \"https\": {\n40         \"enabled\": True,\n41         \"key\": \"api/configuration/ssl/server.key\",\n42         \"cert\": \"api/configuration/ssl/server.crt\",\n43         \"use_ca\": False,\n44         \"ca\": \"api/configuration/ssl/ca.crt\",\n45         \"ssl_protocol\": \"TLSv1.2\",\n46         \"ssl_ciphers\": \"\"\n47     },\n48     \"logs\": {\n49         \"level\": \"info\",\n50         \"path\": \"logs/api.log\"\n51     },\n52     \"cors\": {\n53         \"enabled\": False,\n54         \"source_route\": \"*\",\n55         \"expose_headers\": \"*\",\n56         \"allow_headers\": \"*\",\n57         \"allow_credentials\": False,\n58     },\n59     \"cache\": {\n60         \"enabled\": True,\n61         \"time\": 0.750\n62     },\n63     \"access\": {\n64         \"max_login_attempts\": 50,\n65         \"block_time\": 300,\n66         \"max_request_per_minute\": 300\n67     },\n68     \"remote_commands\": {\n69         \"localfile\": {\n70             \"enabled\": True,\n71             \"exceptions\": []\n72         },\n73         \"wodle_command\": {\n74             \"enabled\": True,\n75             \"exceptions\": []\n76         }\n77     }\n",
            "filename": "api/api/configuration.py",
            "issue_confidence": "MEDIUM",
            "issue_severity": "MEDIUM",
            "issue_text": "Possible binding to all interfaces.",
            "line_number": 30,
            "line_range": [
                29,
                30,
                31,
                32,
                33,
                34,
                35,
                36,
                37,
                38,
                39,
                40,
                41,
                42,
                43,
                44,
                45,
                46,
                47,
                48,
                49,
                50,
                51,
                52,
                53,
                54,
                55,
                56,
                57,
                58,
                59,
                60,
                61,
                62,
                63,
                64,
                65,
                66,
                67,
                68,
                69,
                70,
                71,
                72,
                73,
                74,
                75
            ],
            "more_info": "https://bandit.readthedocs.io/en/latest/plugins/b104_hardcoded_bind_all_interfaces.html",
            "test_id": "B104",
            "test_name": "hardcoded_bind_all_interfaces"
        },
        {
            "code": "                                )\n     app.add_api('spec.yaml',\n                 arguments={'title': 'Wazuh API',\n                            'protocol': 'https' if api_conf['https']['enabled'] else 'http',\n                            'host': api_conf['host'],\n                            'port': api_conf['port']\n                            },\n                 strict_validation=True,\n                 validate_responses=False,\n162                 pass_context_arg_name='request',\n163                 options={\"middlewares\": [response_postprocessing, set_user_name, security_middleware, request_logging,\n164                                          set_secure_headers]})\n165 \n",
            "filename": "api/scripts/wazuh-apid.py",
            "issue_confidence": "MEDIUM",
            "issue_severity": "LOW",
            "issue_text": "Possible hardcoded password: 'request'",
            "line_number": 154,
            "line_range": [
                154,
                155,
                156,
                157,
                158,
                159,
                160,
                161,
                162,
                163,
                164
            ],
            "more_info": "https://bandit.readthedocs.io/en/latest/plugins/b106_hardcoded_password_funcarg.html",
            "test_id": "B106",
            "test_name": "hardcoded_password_funcarg"
        }
    ],
    "to_fix": []
}
```

</details>

If we pass the test again, it will pass.

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
