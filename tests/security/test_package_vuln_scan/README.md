# Package Vulnerability Scanner

## Description
PVS is a tool used to scan for vulnerabilities in a requirements.txt file.\
It can generate reports via console output or json file and can be ran with `pytest` or as a python script.\
If you use it as script, requirements file must be specified locally. Other way to scan for vulnerabilities is checking on `pip freeze` to get packages currently installed on the system (more information below, under `how to use` section).\
Using with pytest, it manage to handle remote files under github repositories. Requirements file can be specified with `repo`, `branch` and `path` parameters giving flexibility on file location.

## How to use
### A - Script
```
⬦⬦⬦ ~/git/wazuh-qa/tests/security/test_package_vuln_scan ⨘ python3 package_vuln_scan.py -h
usage: package_vuln_scan.py [-h] (-r INPUT | -p) [-o OUTPUT]

optional arguments:
  -h, --help  show this help message and exit
  -r INPUT    specify requirements file path.
  -p          enable pip scan mode.
  -o OUTPUT   specify output file.
```
#### pip scan mode with console output:
```
⬦⬦⬦ ~/git/wazuh-qa/tests/security/test_package_vuln_scan ⨘ python3 package_vuln_scan.py -p
{
    "report_date": "2021-08-09T12:17:26.615321",
    "vulnerabilities_found": 0,
    "packages": []
}
```
#### requirements file with json output file:
```
⬦⬦⬦ ~/git/wazuh-qa/tests/security/test_package_vuln_scan ⨘ python3 package_vuln_scan.py -r ~/git/wazuh/framework/requirements.txt -o json_output.json
⬦⬦⬦ ~/git/wazuh-qa/tests/security/test_package_vuln_scan ⨘ cat json_output.json
{
    "report_date": "2021-08-09T12:19:07.675120",
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
	--path: requirements file path. Default: 'framework/requirements.txt'.
```
#### scanning wazuh-qa requirements file:
```
⬦⬦⬦ ~/git/wazuh-qa/tests/security ⨘ python3 -m pytest test_package_vuln_scan/ --repo wazuh-qa --branch master --path requirements.txt
==================================================================================== test session starts =====================================================================================
platform linux -- Python 3.9.5, pytest-5.0.0, py-1.10.0, pluggy-0.13.1
rootdir: /home/kondent/git/wazuh-qa/tests/security
plugins: html-3.1.1, metadata-1.11.0, tavern-1.2.2
collected 1 item

test_package_vuln_scan/test_package_vuln_scan.py F                                                                                                                                     [100%]

========================================================================================== FAILURES ==========================================================================================
___________________________________________________________________________________ test_package_vuln_scan ___________________________________________________________________________________

pytestconfig = <_pytest.config.Config object at 0x7fad7da94a60>

    def test_package_vuln_scan(pytestconfig):
        branch = pytestconfig.getoption('branch')
        repo = pytestconfig.getoption('repo')
        path = pytestconfig.getoption('path')
        requirements_url = f'https://raw.githubusercontent.com/wazuh/{repo}/{branch}/{path}'
        urlretrieve(requirements_url, REQUIREMENTS_TEMP_FILE.name)
        result = report_for_pytest(REQUIREMENTS_TEMP_FILE.name)
        REQUIREMENTS_TEMP_FILE.close()
        export_report(result, REPORT_FILE)
>       assert loads(result)['vulnerabilities_found'] == 0, f'Vulnerables packages were found, full report at: ' \
                                                            f'{REPORT_FILE}'
E       AssertionError: Vulnerables packages were found, full report at: test_package_vuln_scan/report_file.json
E       assert 28 == 0

test_package_vuln_scan/test_package_vuln_scan.py:20: AssertionError
================================================================================== 1 failed in 1.64 seconds ==================================================================================

⬦⬦⬦ ~/git/wazuh-qa/tests/security ⨘ cat test_package_vuln_scan/report_file.json 
{
    "report_date": "2021-08-09T12:22:45.859541",
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
