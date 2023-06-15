# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import os
import tempfile
from json import loads
from urllib.request import urlretrieve

from wazuh_testing.tools.scans.dependencies import export_report, report_for_pytest

REQUIREMENTS_TEMP_FILE = tempfile.NamedTemporaryFile()


def test_python_dependencies_vuln_scan(pytestconfig):
    """Check that the specified dependencies do not have any known vulnerabilities.

    Args:
        pytestconfig (fixture): Fixture that returns the :class:`_pytest.config.Config` object.
    """
    branch = pytestconfig.getoption('--reference')
    repo = pytestconfig.getoption('--repo')
    requirements_path = pytestconfig.getoption('--requirements-path')
    report_path = pytestconfig.getoption('--report-path')
    requirements_url = f"https://raw.githubusercontent.com/wazuh/{repo}/{branch}/{requirements_path}"
    urlretrieve(requirements_url, REQUIREMENTS_TEMP_FILE.name)
    result = report_for_pytest(REQUIREMENTS_TEMP_FILE.name,
                               os.path.join(os.path.dirname(os.path.abspath(__file__)), "known_flaws_deps.json"))
    REQUIREMENTS_TEMP_FILE.close()
    export_report(result, report_path)
    assert loads(result)['vulnerabilities_found'] == 0, f'Vulnerables packages were found, full report at: ' \
                                                        f"{report_path}"
