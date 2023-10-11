# Dependencies Scanner

## Description

The Dependencies Scanner is a tool for scanning vulnerabilities in a *requirements.txt* file from different GitHub repositories. 
It uses `pytest` to run and can generate reports via console output or JSON files.

The requirements file to scan can be specified with the `repo`, `reference`, and `requirements-path` parameters. 
Moreover, the path of the report file generated can be chosen with the `report-path` parameter.

## How to use - Pytest
```
Parameters:
    --repo: repository name. Default: 'wazuh'.
    --reference: branch name of specified repository. Default: 'master'.
    --requirements-path: requirements file path. Default: 'framework/requirements.txt'.
    --report-path: output file path. Default: 'dependencies/report_file.json'.
```
### Scanning wazuh-qa requirements file:

> The script does not support pyenv version changes because it doesn't expect system variables to be modified

```
↪ ~/git/wazuh-qa/tests/scans ⊶ feature/1612-package-vuln-scanner ⨘ python3 -m pytest -vv -x --disable-warnings dependencies/ --repo wazuh-qa --reference master --requirements-path requirements.txt
==================================================================================== test session starts =====================================================================================
platform linux -- Python 3.9.5, pytest-6.2.3, py-1.10.0, pluggy-0.13.1 -- /home/kondent/pythonEnv/qa-env/bin/python3
cachedir: .pytest_cache
metadata: {'Python': '3.9.5', 'Platform': 'Linux-5.11.0-34-generic-x86_64-with-glibc2.31', 'Packages': {'pytest': '6.2.3', 'py': '1.10.0', 'pluggy': '0.13.1'}, 'Plugins': {'html': '3.1.1', 'metadata': '1.11.0', 'testinfra': '5.0.0'}}
rootdir: /home/kondent/git/wazuh-qa/tests/scans
plugins: html-3.1.1, metadata-1.11.0, testinfra-5.0.0
collected 1 item

dependencies/test_dependencies.py::test_python_dependencies_vuln_scan FAILED                                                                                                               [100%]

========================================================================================== FAILURES ==========================================================================================
_______________________________________________________________________________ test_python_dependencies_vuln_scan _______________________________________________________________________________

pytestconfig = <_pytest.config.Config object at 0x7f721b4c4eb0>

    def test_python_dependencies_vuln_scan(pytestconfig):
        branch = pytestconfig.getoption('--branch')
        repo = pytestconfig.getoption('--repo')
        requirements_path = pytestconfig.getoption('--requirements-path')
        report_path = pytestconfig.getoption('--report-path')
        requirements_url = f'https://raw.githubusercontent.com/wazuh/{repo}/{branch}/{requirements_path}'
        urlretrieve(requirements_url, REQUIREMENTS_TEMP_FILE.name)
        result = report_for_pytest(REQUIREMENTS_TEMP_FILE.name)
        REQUIREMENTS_TEMP_FILE.close()
        export_report(result, report_path)
>       assert loads(result)['vulnerabilities_found'] == 0, f'Vulnerables packages were found, full report at: ' \
                                                            f'{report_path}'
E       AssertionError: Vulnerables packages were found, full report at: /home/kondent/git/wazuh-qa/tests/scans/dependencies/report_file.json
E       assert 28 == 0
E         +28
E         -0

dependencies/test_dependencies.py:23: AssertionError
================================================================================== short test summary info ===================================================================================
FAILED dependencies/test_dependencies.py::test_python_dependencies_vuln_scan - AssertionError: Vulnerables packages were found, full report at: /home/kondent/git/wazuh-qa/tests/scans/dependen...
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! stopping after 1 failures !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
===================================================================================== 1 failed in 1.87s ======================================================================================
↪ ~/git/wazuh-qa/tests/scans ⊶ feature/1612-package-vuln-scanner ⨘ cat dependencies/report_file.json
{
    "report_date": "2021-09-10T09:49:43.471148",
    "vulnerabilities_found": 28,
    "packages": [
        {
            "package_name": "pillow",
            "package_version": "6.2.0",
            "package_affected_version": "<6.2.2",
            "vuln_description": "libImaging/TiffDecode.c in Pillow before 6.2.2 has a TIFF decoding integer overflow, related to realloc. See: CVE-2020-5310.",
            "safety_id": "37779"
        },
        ...
        ...
        ...
    ]
}
```

### Scanning wazuh requirements file with a specific output path:
```
↪ ~/git/wazuh-qa/tests/scans ⊶ feature/1612-package-vuln-scanner ⨘ python3 -m pytest -vv -x --disable-warnings dependencies/ --repo wazuh --reference master --requirements-path framework/requirements.txt --report-path ~/Desktop/report_file.json
==================================================================================== test session starts =====================================================================================
platform linux -- Python 3.9.5, pytest-6.2.3, py-1.10.0, pluggy-0.13.1 -- /home/kondent/pythonEnv/qa-env/bin/python3
cachedir: .pytest_cache
metadata: {'Python': '3.9.5', 'Platform': 'Linux-5.11.0-34-generic-x86_64-with-glibc2.31', 'Packages': {'pytest': '6.2.3', 'py': '1.10.0', 'pluggy': '0.13.1'}, 'Plugins': {'html': '3.1.1', 'metadata': '1.11.0', 'testinfra': '5.0.0'}}
rootdir: /home/kondent/git/wazuh-qa/tests/scans
plugins: html-3.1.1, metadata-1.11.0, testinfra-5.0.0
collected 1 item

dependencies/test_dependencies.py::test_python_dependencies_vuln_scan PASSED                                                                                                               [100%]

===================================================================================== 1 passed in 0.68s ======================================================================================
↪ ~/git/wazuh-qa/tests/scans ⊶ feature/1612-package-vuln-scanner ⨘ cat ~/Desktop/report_file.json
{
    "report_date": "2021-09-10T09:53:39.284082",
    "vulnerabilities_found": 0,
    "packages": []
}
```
