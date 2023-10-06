import os
import platform
import re

from wazuh_testing.tools import LOG_FILE_PATH, WAZUH_PATH
from wazuh_testing.tools.file import truncate_file

AR_FOLDER = 'active-response' if platform.system() == 'Windows' else 'logs'
AR_LOG_FILE_PATH = os.path.join(WAZUH_PATH, AR_FOLDER, 'active-responses.log')


def clean_logs():
    """Clean log file."""
    truncate_file(LOG_FILE_PATH)
    truncate_file(AR_LOG_FILE_PATH)


def wait_ended_message_line(line):
    """Callback function to wait for the Ended Active Response message."""
    regex = r'.*active-response\/bin\/\S+: Ended$'
    match = re.match(regex, line)

    return None if not match else line


def wait_received_message_line(line):
    """Callback function to wait for the Received Active Response message."""
    regex = r'.*DEBUG: Received message: .+'
    match = re.match(regex, line)

    return None if not match else line


def wait_start_message_line(line):
    """Callback function to wait for the Starting Active Response message."""
    regex = r'.*active-response\/bin\/\S+: Starting$'
    match = re.match(regex, line)

    return None if not match else line


def wait_firewall_drop_msg(line):
    """Callback function to wait for a JSON message with the AR command.

    Args:
        line (str): String containing message.

    Returns:
        match.group(1): First capturing group which is the JSON message.
    """
    regex = r'.*active-response\/bin\/firewall-drop: (.+)'
    match = re.match(regex, line)

    return None if not match else match.group(1)
