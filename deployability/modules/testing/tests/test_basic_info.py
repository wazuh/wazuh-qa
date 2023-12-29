import os

from .helpers import utils


def test_wazuh_version():
    assert os.environ['to_version'] in utils.get_version(), "Wazuh version is not the expected."


def test_wazuh_revision():
    assert utils.get_revision() == os.environ['revision'], "Wazuh revision is not the expected."
