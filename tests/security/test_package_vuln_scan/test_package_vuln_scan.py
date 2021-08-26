import tempfile
from json import loads
from urllib.request import urlretrieve

from package_vuln_scan import export_report, report_for_pytest

REQUIREMENTS_TEMP_FILE = tempfile.NamedTemporaryFile()


def test_package_vuln_scan(pytestconfig):
    branch = pytestconfig.getoption('--branch')
    repo = pytestconfig.getoption('--repo')
    requirements_path = pytestconfig.getoption('--requirements-path')
    report_path = pytestconfig.getoption('--report-path')
    requirements_url = f'https://raw.githubusercontent.com/wazuh/{repo}/{branch}/{requirements_path}'
    urlretrieve(requirements_url, REQUIREMENTS_TEMP_FILE.name)
    result = report_for_pytest(REQUIREMENTS_TEMP_FILE.name)
    REQUIREMENTS_TEMP_FILE.close()
    export_report(result, report_path)
    assert loads(result)['vulnerabilities_found'] == 0, f'Vulnerables packages were found, full report at: ' \
                                                        f'{report_path}'
