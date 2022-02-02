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


#Error message
ERR_MSG_MAXIMUM_FILE_SIZE = 'Did not receive expected "Maximum file size limit configured to \'... KB\'..." event'
ERR_MSG_WRONG_VALUE_MAXIMUM_FILE_SIZE = 'Wrong value for diff_size_limit'