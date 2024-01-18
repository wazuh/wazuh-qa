import platform
import pytest

from ..helpers import utils
from ..helpers.wazuh_api.api import WazuhAPI


@pytest.fixture()
def agent_uname(wazuh_api: WazuhAPI, agent_id: str) -> dict:
    agent_info = wazuh_api.get_agent(agent_id)
    uname_list = agent_info.get('os').get('uname').split(' ')
    uname = {'system': uname_list[0],
             'node': uname_list[1],
             'release': uname_list[2],
             'version': uname_list[3],
             'machine': uname_list[4]}
    return uname


def test_agent_version(wazuh_version):
    actual_version = utils.get_version()
    assert wazuh_version in actual_version, 'Unexpected agent version.'


def test_agent_revision(wazuh_revision):
    actual_revision = utils.get_revision()
    assert wazuh_revision in actual_revision, 'Unexpected agent version.'


def test_agent_version_on_server(wazuh_api, wazuh_version, agent_id):
    expected_version = wazuh_version
    actual_version = wazuh_api.get_agent(agent_id).get('version')
    assert expected_version in actual_version, 'Unexpected agent version reported by server.'


def test_agent_system(agent_uname):
    expected_system = platform.uname.system
    assert expected_system in agent_uname.get('system'), 'Unexpected OS.'


def test_agent_architecture(agent_uname):
    expected_machine = platform.uname.machine
    assert expected_machine in agent_uname.get('machine'), 'Unexpected architecture.'


def test_agent_os_version(agent_uname):
    expected_release = platform.uname.version
    assert expected_release in agent_uname.get('version'), 'Unexpected OS version.'
