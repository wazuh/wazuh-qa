# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

'''
The purpose of this file is to contain all the variables necessary for FIM in order to be easier to
maintain if one of them changes in the future.
'''

# Variables
SIZE_LIMIT_CONFIGURED_VALUE = 10 * 1024

# Key variables
WINDOWS_HKEY_LOCAL_MACHINE = 'HKEY_LOCAL_MACHINE'
MONITORED_KEY = 'SOFTWARE\\random_key'
MONITORED_KEY_2 = "SOFTWARE\\Classes\\random_key_2"
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

# Yaml Configuration
YAML_CONF_REGISTRY_RESPONSE = 'wazuh_conf_registry_responses_win32.yaml'
YAML_CONF_SYNC_WIN32 = 'wazuh_sync_conf_win32.yaml'
YAML_CONF_DIFF = 'wazuh_conf_diff.yaml'

# Synchronization options
SYNCHRONIZATION_ENABLED = 'SYNCHRONIZATION_ENABLED'
SYNCHRONIZATION_REGISTRY_ENABLED = 'SYNCHRONIZATION_REGISTRY_ENABLED'

# Callbacks message
CB_INTEGRITY_CONTROL_MESSAGE = r'.*Sending integrity control message: (.+)$'
CB_REGISTRY_DBSYNC_NO_DATA = r'.*#!-fim_registry dbsync no_data (.+)'
CB_MAXIMUM_FILE_SIZE = r'.*Maximum file size limit to generate diff information configured to \'(\d+) KB\'.*'
CB_FILE_LIMIT_CAPACITY = r".*Sending DB (\d+)% full alert."
CB_FILE_LIMIT_BACK_TO_NORMAL = r".*(Sending DB back to normal alert)."
CB_COUNT_REGISTRY_FIM_ENTRIES = r".*Fim registry entries: (\d+)"
CB_DATABASE_FULL_COULD_NOT_INSERT = r".*Couldn't insert '.*' (value )?entry into DB\. The DB is full.*"
CB_FILE_LIMIT_VALUE = r".*Maximum number of entries to be monitored: '(\d+)'"
CB_FILE_SIZE_LIMIT_BIGGER_THAN_DISK_QUOTA = r".*Setting 'disk_quota' to (\d+), 'disk_quota' must be greater than 'file_size'"

#Error Messages
ERR_MSG_MAXIMUM_FILE_SIZE = 'Did not receive expected "Maximum file size limit configured to \'... KB\'..." event'
ERR_MSG_WRONG_VALUE_MAXIMUM_FILE_SIZE = 'Wrong value for diff_size_limit' 
ERR_MSG_DATABASE_PERCENTAGE_FULL_ALERT = 'Did not receive expected "DEBUG: ...: Sending DB ...% full alert." event'
ERR_MSG_FIM_INODE_ENTRIES = 'Did not receive expected "Fim inode entries: ..., path count: ..." event'
ERR_MSG_DB_BACK_TO_NORMAL = 'Did not receive expected "DEBUG: ...: Sending DB back to normal alert." event'
ERR_MSG_WRONG_NUMBER_OF_ENTRIES = 'Wrong number of entries counted.'
ERR_MSG_WRONG_FILE_LIMIT_VALUE ='Wrong value for file_limit.'
ERR_MSG_WRONG_DISK_QUOTA_VALUE ='Wrong value for disk_quota'
ERR_MSG_DATABASE_FULL_ALERT_EVENT = 'Did not receive expected "DEBUG: ...: Sending DB 100% full alert." event'
ERR_MSG_DATABASE_FULL_COULD_NOT_INSERT = 'Did not receive expected "DEBUG: ...: Couldn\'t insert \'...\' entry into DB. The DB is full, ..." event'
ERR_MSG_FILE_LIMIT_VALUES = 'Did not receive expected "DEBUG: ...: Maximum number of entries to be monitored: ..." event'
ERR_MSG_WRONG_VALUE_FOR_DATABASE_FULL = 'Wrong value for full database alert.'
ERR_MSG_DISK_QUOTA_MUST_BE_GREATER = "Did not receive expected 'DEBUG: ... disk_quota must be greater than file_size message'"
ERR_MSG_CONTENT_CHANGES_EMPTY = "content_changes is empty"
ERR_MSG_CONTENT_CHANGES_NOT_EMPTY = "content_changes isn't empty"
