from helpers import utils
from helpers.constants import DELETING_RESPONSES, RELEASING_RESOURCES, STARTED, WAZUH_LOG


# Actual running service.
service = utils.get_service()


def test_release_resources_shutdown_log_raised():
    assert utils.file_monitor(WAZUH_LOG, RELEASING_RESOURCES), "Release resources log not found."


def test_deleting_responses_shutdown_log_raised():
    assert utils.file_monitor(WAZUH_LOG, DELETING_RESPONSES), "Deleting responses log not found."


def test_start_log_raised():
    assert utils.file_monitor(WAZUH_LOG, STARTED), "Start log not found."


def test_service_started():
    assert utils.get_service_status() == "active", "Service is not active after restart."
