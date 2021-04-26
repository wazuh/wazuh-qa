import os
import platform

from wazuh_testing.tools import LOG_FILE_PATH, WAZUH_PATH, get_version
from wazuh_testing.tools.file import truncate_file

AR_FOLDER = 'active-response' if platform.system() == 'Windows' else 'logs'
AR_LOG_FILE_PATH = os.path.join(WAZUH_PATH, AR_FOLDER, 'active-responses.log')


def clean_logs():
    """Clean log file."""
    truncate_file(LOG_FILE_PATH)
    truncate_file(AR_LOG_FILE_PATH)


def wait_ended_message_line(line):
    """Callback function to wait for the Ended Active Response message."""
    return True if "Ended" in line else None


def wait_received_message_line(line):
    """Callback function to wait for the Received Active Response message."""
    return True if "DEBUG: Received message: " in line else None


def wait_start_message_line(line):
    """Callback function to wait for the Starting Active Response message."""
    return True if "Starting" in line else None
