import platform
import pytest


@pytest.fixture
def wazuh_params(request):

    return {
        'wazuh_version': request.config.getoption('--wazuh_version')
    }

@pytest.fixture(scope='module')
def agent_uname(agent_info: dict) -> dict:
    uname_list = agent_info.get('os').get('uname').split('|')
    uname = {'system': uname_list[0],
             'node': uname_list[1],
             'release': uname_list[2],
             'version': uname_list[3],
             'machine': uname_list[4]}

    return uname

def test_agent_version(wazuh_params: dict, agent_info: dict) -> None:
    expected_version = f"Wazuh v{wazuh_params['wazuh_version']}"
    actual_version = agent_info.get('version')
    assert expected_version in actual_version, 'Unexpected agent version reported by server.'

def test_agent_system(agent_uname: dict) -> None:
    expected_system = platform.uname().system
    assert expected_system in agent_uname.get('system'), 'Unexpected OS.'

def test_agent_architecture(agent_uname: dict) -> None:
    expected_machine = platform.uname().machine
    assert expected_machine in agent_uname.get('machine'), 'Unexpected architecture.'

def test_agent_os_version(agent_uname: dict) -> None:
    expected_release = platform.uname().version
    assert expected_release in agent_uname.get('version'), 'Unexpected OS version.'
