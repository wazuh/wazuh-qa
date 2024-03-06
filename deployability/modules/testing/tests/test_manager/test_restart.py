import grp
import pwd
import pytest
import json
import re

from ..helpers.manager import WazuhManager
from ..helpers.generic import HostConfiguration, HostInformation
wazuh_manager = WazuhManager()
host_configuration = HostConfiguration()


def wazuh_params(request):
    wazuh_version = request.config.getoption('--wazuh_version')
    wazuh_revision = request.config.getoption('--wazuh_revision')
    dependencies = request.config.getoption('--dependencies')
    inventory = request.config.getoption('--inventory')

    return {
        'wazuh_version': wazuh_version,
        'wazuh_revision': wazuh_revision,
        'dependencies': dependencies,
        'inventory': inventory

    }

def test_restart(wazuh_params):
    

    wazuh_manager.manager_restart(wazuh_params['dependencies']['manager'])

    assert 'active ' in wazuh_manager.get_manager_status(wazuh_params['inventory'])
    assert 'active ' in wazuh_manager.get_manager_status(wazuh_params['dependencies']['manager'])


