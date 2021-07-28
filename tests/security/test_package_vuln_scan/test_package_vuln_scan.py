import tempfile
from json import loads
from urllib.request import urlretrieve

from package_vuln_scan import export_report, report_for_pytest

REQUIREMENTS_TEMP_FILE = tempfile.NamedTemporaryFile()
REPORT_FILE = 'test_package_vuln_scan/report_file.json'


def test_package_vuln_scan(pytestconfig):
    branch = pytestconfig.getoption('branch')
    repo = pytestconfig.getoption('repo')
    path = pytestconfig.getoption('path')
    requirements_url = f'https://raw.githubusercontent.com/wazuh/{repo}/{branch}/{path}'
    urlretrieve(requirements_url, REQUIREMENTS_TEMP_FILE.name)
    result = report_for_pytest(REQUIREMENTS_TEMP_FILE.name)
    REQUIREMENTS_TEMP_FILE.close()
    export_report(result, REPORT_FILE)
    assert loads(result)['vulnerabilities_found'] == 0, f'Vulnerables packages were found, full report at: ' \
                                                        f'{REPORT_FILE}'
