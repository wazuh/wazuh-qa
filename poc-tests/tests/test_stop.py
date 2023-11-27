import pytest

from .helpers import utils
from .helpers.constants import DELETING_RESPONSES, RELEASING_RESOURCES, WAZUH_CONTROL, WAZUH_LOG


# Actual running service.
service = utils.get_service()


@pytest.fixture(scope='module', autouse=True)
def stop_wazuh():
    component = 'wazuh-agent' if service == 'agent' else 'wazuh-manager'
    utils.run_command(WAZUH_CONTROL, ['stop'])
    utils.run_command('systemctl', ['stop', component])


def test_release_resources_shutdown_log_raised():
    assert utils.file_monitor(
        WAZUH_LOG, RELEASING_RESOURCES), "Release resources log not found."


def test_deleting_responses_shutdown_log_raised():
    assert utils.file_monitor(
        WAZUH_LOG, DELETING_RESPONSES), "Deleting responses log not found."


def test_service_started():
    assert utils.get_service_status() == "inactive", "Service is active."
