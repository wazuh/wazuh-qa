"""
Regex Patterns for Syscollector Events.
---------------------------------------

This module defines regular expression patterns for various events related to Syscollector.
The patterns are used to extract information from log messages.

Constants:
    REGEX_PATTERNS (dict): A dictionary mapping event names to their respective regex patterns and parameters.

Functions:
    get_event_regex: Get the regex pattern for a specific event.


Copyright (C) 2015, Wazuh Inc.
Created by Wazuh, Inc. <info@wazuh.com>.
This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2
"""
from typing import Dict
import logging


REGEX_PATTERNS = {
    'syscollector_scan_start': {
        'regex': r'(\d{4}\/\d{2}\/\d{2} \d{2}:\d{2}:\d{2}) .*? INFO: Starting evaluation'
    },
    'syscollector_scan_end': {
        'regex': r'(\d{4}\/\d{2}\/\d{2} \d{2}:\d{2}:\d{2}) .*? INFO: Evaluation finished'
    },
    'syscollector_install_package_alert_yum': {
        'regex': '.*installed.*agent".*"name":"(\\S+)".*Installed: (\\S+).*?(\\S+)',
        'parameters': ['PACKAGE_NAME', 'PACKAGE_VERSION', 'HOST_NAME']
    },
    'syscollector_install_package_alert_apt': {
        'regex': '.*New dpkg  \\(Debian Package\\) installed.*.*agent".*"name":"(\\S+).*package":"(\\S+)",'
        '"arch":"amd64","version":"(\\S+)"',
        'parameters': ['HOST_NAME', 'PACKAGE_NAME', 'PACKAGE_VERSION']
    },
    'syscollector_upgrade_package_alert_yum': {
        'regex': '.*Yum package updated.*agent".*"name":"(\\S+)".*Updated: (\\S+).*?(\\S+)',
        'parameters': ['PACKAGE_NAME', 'PACKAGE_VERSION', 'HOST_NAME']
    },
    'vulnerability_alert': {
        'regex': '.*HOST_NAME.*package":.*name":"PACKAGE_NAME".*version":"PACKAGE_VERSION".*"'
        'architecture":"ARCHITECTURE.*"cve":"CVE"',
        'parameters': ['HOST_NAME', 'CVE', 'PACKAGE_NAME', 'PACKAGE_VERSION', 'ARCHITECTURE']
    },
    'vuln_affected': {
        'regex':  'CVE.* affects.*"?'
    },
    'vuln_mitigated': {
        'regex': "The .* that affected .* was solved due to an update in the agent or feed.*"
    }
}


def get_event_regex(event: Dict) -> str:
    """
    Get the regex pattern for a specific event.

    Args:
        event (dict): Dictionary containing the event information.

    Returns:
        str: The regex pattern for the specified event.

    Raises:
        Exception: If required parameters are missing.

    Example of event:
        {
            'event': 'syscollector_install_package_alert_yum',
            'parameters': {
                'HOST_NAME': 'agent1',
                'PACKAGE_NAME': 'openssh-server',
                'PACKAGE_VERSION': '8.0p1-4',
                'ARCHITECTURE': 'x86_64'
            }
        }
    """
    logging.info(f"Getting regex for event {event['event']}")

    expected_event = REGEX_PATTERNS.get(event['event'])

    if expected_event is None:
        raise Exception(f"Invalid event: {event['event']}")

    expected_regex = expected_event['regex']

    if 'parameters' in expected_event and 'parameters' not in event:
        raise Exception(f"Not provided enough data to create regex. Missing {expected_event['parameters']}")
    elif 'parameters' in event:
        for parameter in expected_event['parameters']:
            expected_regex = expected_regex.replace(parameter, event['parameters'].get(parameter, ''))

    return expected_regex
