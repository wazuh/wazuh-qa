'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.
           Created by Wazuh, Inc. <info@wazuh.com>.
           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
'''
from wazuh_testing.tools import ANALYSISD_DAEMON, DB_DAEMON, INTEGRATOR_DAEMON

# Variables
INTEGRATORD_PREFIX = INTEGRATOR_DAEMON
REQUIRED_DAEMONS = [INTEGRATOR_DAEMON, DB_DAEMON, ANALYSISD_DAEMON]
TIME_TO_DETECT_FILE = 2

# Callback Messages
CB_SLACK_ENABLED = fr".*{INTEGRATORD_PREFIX}.*Enabling integration for: 'slack'.*"
CB_INTEGRATORD_SENDING_ALERT = fr".*{INTEGRATORD_PREFIX}.*DEBUG: sending new alert"
CB_PROCESSING_ALERT = fr".*{INTEGRATORD_PREFIX}.*Processing alert.*"
CB_INTEGRATORD_THREAD_READY = fr".*{INTEGRATORD_PREFIX}.*DEBUG: Local requests thread ready"
CB_SLACK_ALERT = fr".*{INTEGRATORD_PREFIX}.*<Response \[200\]>"
CB_INVALID_JSON_ALERT_READ = fr".*{INTEGRATORD_PREFIX}.*WARNING: Invalid JSON alert read.*"
CB_OVERLONG_JSON_ALERT_READ = fr".*{INTEGRATORD_PREFIX}.*WARNING: Overlong JSON alert read.*"
CB_ALERTS_FILE_INODE_CHANGED = fr".*{INTEGRATORD_PREFIX}.*DEBUG: jqueue_next.*Alert file inode changed.*"
CB_CANNOT_RETRIEVE_JSON_FILE = fr".*{INTEGRATORD_PREFIX}.*WARNING.*Could not retrieve information of file.*"\
                               r'alerts\.json.*No such file.*'

# Error messages
ERR_MSG_SLACK_ENABLED_NOT_FOUND = r'Did not recieve the expected "Enabling integration for slack"'
ERR_MSG_SENDING_ALERT_NOT_FOUND = r'Did not recieve the expected "...sending new alert" event'
ERR_MSG_PROCESSING_ALERT_NOT_FOUND = r'Did not recieve the expected "...Procesing alert" event'
ERR_MSG_SLACK_ALERT_NOT_DETECTED = r'Did not recieve the expected Slack alert in alerts.json'
ERR_MSG_INVALID_ALERT_NOT_FOUND = r'Did not recieve the expected "...Invalid JSON alert read..." event'
ERR_MSG_OVERLONG_ALERT_NOT_FOUND = r'Did not recieve the expected "...Overlong JSON alert read..." event'
ERR_MSG_ALERT_INODE_CHANGED_NOT_FOUND = r'Did not recieve the expected "...Alert file inode changed..." event'
ERR_MSG_CANNOT_RETRIEVE_MSG_NOT_FOUND = r'Did not recieve the expected "...Could not retrieve information/open file"'
