# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

'''
The purpose of this file is to contain all the variables necessary for FIM in order to be easier to
maintain if one of them changes in the future.
'''

# Variables

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

# FIM modules
SCHEDULE_MODE = 'scheduled'

# Yaml Configuration
YAML_CONF_REGISTRY_RESPONSE = 'wazuh_conf_registry_responses_win32.yaml'
YAML_CONF_SYNC_WIN32 = 'wazuh_sync_conf_win32.yaml'

# Synchronization options
SYNCHRONIZATION_ENABLED = 'SYNCHRONIZATION_ENABLED'
SYNCHRONIZATION_REGISTRY_ENABLED = 'SYNCHRONIZATION_REGISTRY_ENABLED'

# Callbacks message
INTEGRITY_CONTROL_MESSAGE = r'.*Sending integrity control message: (.+)$'
REGISTRY_DBSYNC_NO_DATA = r'.*#!-fim_registry dbsync no_data (.+)'
CB_FILE_LIMIT_CAPACITY = r".*Sending DB (\d+)% full alert."
CB_FILE_LIMIT_BACK_TO_NORMAL = r".*(Sending DB back to normal alert)."
CB_COUNT_REGISTRY_FIM_ENTRIES = r".*Fim registry entries: (\d+)"
CB_DATABASE_FULL_ALERT_EVENT = r".*Sending DB (\d+)% full alert."
CB_DATABASE_FULL_COULD_NOT_INSERT = r".*Couldn't insert '.*' (value )?entry into DB\. The DB is full.*"
CB_FILE_LIMIT_VALUE = r".*Maximum number of entries to be monitored: '(\d+)'"

#Error Messages
ERR_MSG_DATABASE_PERCENTAGE_FULL_ALERT = 'Did not receive expected "DEBUG: ...: Sending DB ...% full alert." event'
ERR_MSG_FIM_INODE_ENTRIES = 'Did not receive expected "Fim inode entries: ..., path count: ..." event'
ERR_MSG_DB_BACK_TO_NORMAL = 'Did not receive expected "DEBUG: ...: Sending DB back to normal alert." event'
ERR_MSG_WRONG_NUMBER_OF_ENTRIES = 'Wrong number of entries counted.'
ERR_MSG_DATABASE_FULL_ALERT_EVENT = 'Did not receive expected "DEBUG: ...: Sending DB 100% full alert." event'
ERR_MSG_DATABASE_FULL_COULD_NOT_INSERT = 'Did not receive expected "DEBUG: ...: Couldn\'t insert \'...\' entry into DB. The DB is full, ..." event'
ERR_MSG_FILE_LIMIT_VALUES = 'Did not receive expected "DEBUG: ...: Maximum number of entries to be monitored: ..." event'