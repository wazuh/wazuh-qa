# Package Vulnerability Scanner

## Description
PVS is a tool used to scan for vulnerabilities in a requirements.txt file.\
It can generate reports via console output or json file and can be run with `pytest` or as a python script.\
If you use it as a script, the requirements file must be specified locally. Another way to scan for vulnerabilities is checking on `pip freeze` to get packages currently installed on the system (more information below, under `how to use` section).\
Using along with pytest, it manage to handle remote files under github repositories. Requirements file can be specified with `repo`, `branch` and `path` parameters giving flexibility on file location.

## How to use
### A - Script
```
↪ ~/git/wazuh-qa/tests/security/test_python_packages_vuln_scan ⊶ feature/1612-package-vuln-scanner ⨘ python3 python_packages_vuln_scan.py -h
usage: python_packages_vuln_scan.py [-h] (-r INPUT | -p) [-o OUTPUT]

optional arguments:
  -h, --help  show this help message and exit
  -r INPUT    specify requirements file path.
  -p          enable pip scan mode.
  -o OUTPUT   specify output file.
```
#### pip scan mode with console output:
```
↪ ~/git/wazuh-qa/tests/security/test_python_packages_vuln_scan ⊶ feature/1612-package-vuln-scanner ⨘ python3 python_packages_vuln_scan.py -p
{
    "report_date": "2021-09-02T09:22:40.224599",
    "vulnerabilities_found": 0,
    "packages": []
}
```
#### requirements file with json output file:
```
↪ ~/git/wazuh-qa/tests/security/test_python_packages_vuln_scan ⊶ feature/1612-package-vuln-scanner ⨘ python3 python_packages_vuln_scan.py -r ~/git/wazuh/framework/requirements.txt -o json_output.json
↪ ~/git/wazuh-qa/tests/security/test_python_packages_vuln_scan ⊶ feature/1612-package-vuln-scanner ⨘ cat json_output.json 
{
    "report_date": "2021-09-02T09:23:09.390008",
    "vulnerabilities_found": 0,
    "packages": []
}
```
---
### B - Pytest
```
Parameters:
    --repo: repository name. Default: 'wazuh'.
    --branch: branch name of specified repository. Default: 'master'.
    --requirements-path: requirements file path. Default: 'framework/requirements.txt'.
    --report-path: output file path. Default: 'test_python_packages_vuln_scan/report_file.json'.
```
#### scanning wazuh-qa requirements file:
```
↪ ~/git/wazuh-qa/tests/security ⊶ feature/1612-package-vuln-scanner ⨘ python3 -m pytest test_python_packages_vuln_scan/ --repo wazuh-qa --branch master --requirements-path requirements.txt --report-path ~/Desktop/report_file.json
==================================================================================== test session starts =====================================================================================
platform linux -- Python 3.9.5, pytest-6.2.3, py-1.10.0, pluggy-0.13.1
rootdir: /home/kondent/git/wazuh-qa/tests/security
plugins: html-3.1.1, metadata-1.11.0, testinfra-5.0.0
collected 1 item                                                                                                                                                                             

test_python_packages_vuln_scan/test_python_packages_vuln_scan.py F                                                                                                                     [100%]

========================================================================================== FAILURES ==========================================================================================
_______________________________________________________________________________ test_python_packages_vuln_scan _______________________________________________________________________________

pytestconfig = <_pytest.config.Config object at 0x7f11d3b87e20>

    def test_python_packages_vuln_scan(pytestconfig):
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
E       AssertionError: Vulnerables packages were found, full report at: /home/kondent/Desktop/report_file.json
E       assert 28 == 0

test_python_packages_vuln_scan/test_python_packages_vuln_scan.py:23: AssertionError
====================================================================================== warnings summary ======================================================================================
test_python_packages_vuln_scan/python_packages_vuln_scan.py:82
  /home/kondent/git/wazuh-qa/tests/security/test_python_packages_vuln_scan/python_packages_vuln_scan.py:82: DeprecationWarning: invalid escape sequence \d
    package_version = max(re.findall('\d+\.+\d*\.*\d', line))

-- Docs: https://docs.pytest.org/en/stable/warnings.html
================================================================================== short test summary info ===================================================================================
FAILED test_python_packages_vuln_scan/test_python_packages_vuln_scan.py::test_python_packages_vuln_scan - AssertionError: Vulnerables packages were found, full report at: /home/kondent/De...
================================================================================ 1 failed, 1 warning in 1.44s ================================================================================

↪ ~/git/wazuh-qa/tests/security ⊶ feature/1612-package-vuln-scanner ⨘ cat ~/Desktop/report_file.json 
{
    "report_date": "2021-09-02T09:24:54.168627",
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
        {
            "package_name": "pillow",
            "package_version": "6.2.0",
            "package_affected_version": ">6.0,<6.2.2",
            "vuln_description": "There is a DoS vulnerability in Pillow before 6.2.2 caused by FpxImagePlugin.py calling the range function on an unvalidated 32-bit integer if the number of bands is large. On Windows running 32-bit Python, this results in an OverflowError or MemoryError due to the 2 GB limit. However, on Linux running 64-bit Python this results in the process being terminated by the OOM killer. See: CVE-2019-19911.",
            "safety_id": "37772"
        }
    ]
}
```
