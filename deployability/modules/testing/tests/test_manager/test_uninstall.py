import grp
import pwd
import pytest

from ..helpers import constants, utils
from ..helpers.uninstaller import WazuhManagerUninstaller
from ..helpers.checkfiles import CheckFile
from ..helpers.hostinformation import HostInformation


@pytest.fixture
def wazuh_params(request):
    return {
        'wazuh_version': request.config.getoption('--wazuh_version'),
        'live': request.config.getoption('--live')
    }

def test_uninstallation(wazuh_params):
    aws_s3 = 'packages' if wazuh_params['live'] else 'packages-dev'

    hostinfo= HostInformation()
    uninstall_args = (
        hostinfo.get_linux_distribution(),
        'all',
        wazuh_params['wazuh_version'][0:3],
        aws_s3
    )
    checkfile= CheckFile()
    wazuh_uninstaller= WazuhManagerUninstaller(*uninstall_args)
    result = checkfile.perform_action_and_scan(lambda: wazuh_uninstaller.uninstall_central_components())
    print(result)
    assert all('wazuh' in path or 'ossec' in path for path in result['removed'])
    assert not any('wazuh' in path or 'ossec' in path for path in result['added'])