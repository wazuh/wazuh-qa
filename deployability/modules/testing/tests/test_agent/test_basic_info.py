import os

from ..helpers import utils


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



