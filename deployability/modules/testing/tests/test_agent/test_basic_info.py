import os

from ..helpers import utils


def test_wazuh_version(wazuh_version):
    assert wazuh_version in utils.get_version(), "Wazuh version is not the expected."


def test_wazuh_revision(wazuh_revision):
    assert wazuh_revision in utils.get_revision(), "Wazuh revision is not the expected."
