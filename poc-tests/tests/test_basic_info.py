import os

from helpers import utils


def test_wazuh_version():
    assert utils.get_version() == os.environ['version'], "Wazuh version is not the expected."


def test_wazuh_revision():
    assert utils.get_revision() == os.environ['revision'], "Wazuh revision is not the expected."
    
