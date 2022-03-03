# Copyright (C) 2015-2022, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

'''
The purpose of this file is to contain all the variables necessary for FIM in order to be easier to
maintain if one of them changes in the future.
'''

import sys

# Variables

# Key variables
WINDOWS_HKEY_LOCAL_MACHINE = 'HKEY_LOCAL_MACHINE'
MONITORED_KEY = 'SOFTWARE\\random_key'
WINDOWS_REGISTRY = 'WINDOWS_REGISTRY'


# Value key
SYNC_INTERVAL = 'SYNC_INTERVAL'
SYNC_INTERVAL_VALUE = MAX_EVENTS_VALUE = 20


# Folders variables
TEST_DIR_1 = 'testdir1'
TEST_DIRECTORIES = 'TEST_DIRECTORIES'
TEST_REGISTRIES = 'TEST_REGISTRIES'


# Syscheck attributes
REPORT_CHANGES = 'report_changes'
DIFF_SIZE_LIMIT = 'diff_size_limit'
FILE_SIZE_ENABLED = 'FILE_SIZE_ENABLED'
FILE_SIZE_LIMIT = 'FILE_SIZE_LIMIT'
DISK_QUOTA_ENABLED = 'DISK_QUOTA_ENABLED'
DISK_QUOTA_LIMIT = 'DISK_QUOTA_LIMIT'

# Syscheck values
DIFF_LIMIT_VALUE = 2
DIFF_DEFAULT_LIMIT_VALUE = 51200


# FIM modules
SCHEDULE_MODE = 'scheduled'
REALTIME_MODE = 'realtime'
WHODATA_MODE = 'whodata'


# Yaml Configuration
YAML_CONF_REGISTRY_RESPONSE = 'wazuh_conf_registry_responses_win32.yaml'
YAML_CONF_SYNC_WIN32 = 'wazuh_sync_conf_win32.yaml'
YAML_CONF_DIFF = 'wazuh_conf_diff.yaml'
YAML_CONF_MAX_EPS_SYNC = 'wazuh_sync_conf_max_eps.yaml'

# Synchronization options
SYNCHRONIZATION_ENABLED = 'SYNCHRONIZATION_ENABLED'
SYNCHRONIZATION_REGISTRY_ENABLED = 'SYNCHRONIZATION_REGISTRY_ENABLED'

# Callbacks message
CB_INTEGRITY_CONTROL_MESSAGE = r'.*Sending integrity control message: (.+)$'
CB_REGISTRY_DBSYNC_NO_DATA = r'.*#!-fim_registry dbsync no_data (.+)'
CB_MAXIMUM_FILE_SIZE = r'.*Maximum file size limit to generate diff information configured to \'(\d+) KB\'.*'
CB_AGENT_CONNECT = r'.* Connected to the server .*'
CB_INODE_ENTRIES_PATH_COUNT = r".*Fim inode entries: '(\d+)', path count: '(\d+)'"
CB_FILE_LIMIT_CAPACITY = r".*File database is (\d+)% full."
CB_FILE_LIMIT_BACK_TO_NORMAL = r".*(Sending DB back to normal alert)."
CB_FIM_ENTRIES_COUNT =r".*Fim entries: (\d+)"
CB_FILE_LIMIT_VALUE = r".*Maximum number of files to be monitored: '(\d+)'"
CB_DETECT_FIM_EVENT = r'.*Sending FIM event: (.+)$'
CB_DATABASE_FULL_COULD_NOT_INSERT = r".*Couldn't insert '('.*')?' entry into DB\. The DB is full.*"
CB_FILE_LIMIT_DISABLED = r".*(No limit set) to maximum number of entries to be monitored"


# Error message
ERR_MSG_MAXIMUM_FILE_SIZE = 'Did not receive expected "Maximum file size limit configured to \'... KB\'..." event'
ERR_MSG_WRONG_VALUE_MAXIMUM_FILE_SIZE = 'Wrong value for diff_size_limit'
ERR_MSG_AGENT_DISCONNECT = 'Agent couldn\'t connect to server.'
ERR_MSG_INTEGRITY_CONTROL_MSG = 'Didn\'t receive control message(integrity_check_global)'
ERR_MSG_DATABASE_PERCENTAGE_FULL_ALERT = 'Did not receive expected "DEBUG: ...: Sending DB ...% full alert." event'
ERR_MSG_WRONG_CAPACITY_LOG_DB_LIMIT= 'Wrong capacity log for DB file_limit'
ERR_MSG_WRONG_NUMBER_OF_ENTRIES = 'Wrong number of entries counted.'
ERR_MSG_WRONG_INODE_PATH_COUNT = 'Wrong number of inodes and path count'
ERR_MSG_DB_BACK_TO_NORMAL = 'Did not receive expected "DEBUG: ...: Sending DB back to normal alert." event'
ERR_MSG_FIM_INODE_ENTRIES = 'Did not receive expected "Fim inode entries: ..., path count: ..." event'
ERR_MSG_FILE_LIMIT_VALUES = 'Did not receive expected "DEBUG: ...: Maximum number of entries to be monitored: ..." event'
ERR_MSG_WRONG_FILE_LIMIT_VALUE ='Wrong value for file_limit.'
ERR_MSG_DATABASE_FULL_ALERT_EVENT = 'Did not receive expected "DEBUG: ...: Sending DB 100% full alert." event'
ERR_MSG_WRONG_VALUE_FOR_DATABASE_FULL = 'Wrong value for full database alert.'
ERR_MSG_NO_EVENTS_EXPECTED = 'No events should be detected.'
ERR_MSG_DELETED_EVENT_NOT_RECIEVED = 'Did not receive expected deleted event'
ERR_MSG_DATABASE_FULL_COULD_NOT_INSERT = 'Did not receive expected "DEBUG: ...: Couldn\'t insert \'...\' entry into DB. The DB is full, ..." event'
ERR_MSG_FILE_LIMIT_DISABLED = 'Did not receive expected "DEBUG: ...: No limit set to maximum number of entries to be monitored" event'


# Setting Local_internal_option file

if sys.platform == 'win32':
    FIM_DEFAULT_LOCAL_INTERNAL_OPTIONS = {
        'windows.debug': '2',
        'syscheck.debug': '2',
        'agent.debug': '2',
        'monitord.rotate_log': '0'
    }
else:
    FIM_DEFAULT_LOCAL_INTERNAL_OPTIONS = {
        'syscheck.debug': '2',
        'agent.debug': '2',
        'monitord.rotate_log': '0'
    }
