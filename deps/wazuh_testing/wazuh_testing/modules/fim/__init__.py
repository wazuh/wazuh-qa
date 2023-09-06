# Copyright (C) 2015-2023, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

'''
The purpose of this file is to contain all the variables necessary for FIM in order to be easier to
maintain if one of them changes in the future.
'''

import sys
import os
from wazuh_testing.tools import PREFIX

if sys.platform == 'win32':
    import win32con
    import win32api


# Variables
SIZE_LIMIT_CONFIGURED_VALUE = 10240

if sys.platform == 'win32':

    registry_parser = {
        'HKEY_CLASSES_ROOT': win32con.HKEY_CLASSES_ROOT,
        'HKEY_CURRENT_USER': win32con.HKEY_CURRENT_USER,
        'HKEY_LOCAL_MACHINE': win32con.HKEY_LOCAL_MACHINE,
        'HKEY_USERS': win32con.HKEY_USERS,
        'HKEY_CURRENT_CONFIG': win32con.HKEY_CURRENT_CONFIG
    }

    registry_class_name = {
        win32con.HKEY_CLASSES_ROOT: 'HKEY_CLASSES_ROOT',
        win32con.HKEY_CURRENT_USER: 'HKEY_CURRENT_USER',
        win32con.HKEY_LOCAL_MACHINE: 'HKEY_LOCAL_MACHINE',
        win32con.HKEY_USERS: 'HKEY_USERS',
        win32con.HKEY_CURRENT_CONFIG: 'HKEY_CURRENT_CONFIG'
    }

    registry_value_type = {
        win32con.REG_NONE: 'REG_NONE',
        win32con.REG_SZ: 'REG_SZ',
        win32con.REG_EXPAND_SZ: 'REG_EXPAND_SZ',
        win32con.REG_BINARY: 'REG_BINARY',
        win32con.REG_DWORD: 'REG_DWORD',
        win32con.REG_DWORD_BIG_ENDIAN: 'REG_DWORD_BIG_ENDIAN',
        win32con.REG_LINK: 'REG_LINK',
        win32con.REG_MULTI_SZ: 'REG_MULTI_SZ',
        win32con.REG_RESOURCE_LIST: 'REG_RESOURCE_LIST',
        win32con.REG_FULL_RESOURCE_DESCRIPTOR: 'REG_FULL_RESOURCE_DESCRIPTOR',
        win32con.REG_RESOURCE_REQUIREMENTS_LIST: 'REG_RESOURCE_REQUIREMENTS_LIST',
        win32con.REG_QWORD: 'REG_QWORD'
    }

    REG_NONE = win32con.REG_NONE
    REG_SZ = win32con.REG_SZ
    REG_EXPAND_SZ = win32con.REG_EXPAND_SZ
    REG_BINARY = win32con.REG_BINARY
    REG_DWORD = win32con.REG_DWORD
    REG_DWORD_BIG_ENDIAN = win32con.REG_DWORD_BIG_ENDIAN
    REG_LINK = win32con.REG_LINK
    REG_MULTI_SZ = win32con.REG_MULTI_SZ
    REG_RESOURCE_LIST = win32con.REG_RESOURCE_LIST
    REG_FULL_RESOURCE_DESCRIPTOR = win32con.REG_FULL_RESOURCE_DESCRIPTOR
    REG_RESOURCE_REQUIREMENTS_LIST = win32con.REG_RESOURCE_REQUIREMENTS_LIST
    REG_QWORD = win32con.REG_QWORD
    KEY_WOW64_32KEY = win32con.KEY_WOW64_32KEY
    KEY_WOW64_64KEY = win32con.KEY_WOW64_64KEY
    KEY_ALL_ACCESS = win32con.KEY_ALL_ACCESS
    RegOpenKeyEx = win32api.RegOpenKeyEx
    RegCloseKey = win32api.RegCloseKey
else:

    registry_parser = {}
    registry_class_name = {}
    registry_value_type = {}
    RegOpenKeyEx = 0
    RegCloseKey = 0
    KEY_WOW64_32KEY = 0
    KEY_WOW64_64KEY = 0
    REG_NONE = 0
    REG_SZ = 0
    REG_EXPAND_SZ = 0
    REG_BINARY = 0
    REG_DWORD = 0
    REG_DWORD_BIG_ENDIAN = 0
    REG_LINK = 0
    REG_MULTI_SZ = 0
    REG_RESOURCE_LIST = 0
    REG_FULL_RESOURCE_DESCRIPTOR = 0
    REG_RESOURCE_REQUIREMENTS_LIST = 0
    REG_QWORD = 0
    KEY_ALL_ACCESS = 0


# Check Types
CHECK_ALL = 'check_all'
CHECK_SUM = 'check_sum'
CHECK_SHA1SUM = 'check_sha1sum'
CHECK_MD5SUM = 'check_md5sum'
CHECK_SHA256SUM = 'check_sha256sum'
CHECK_SIZE = 'check_size'
CHECK_OWNER = 'check_owner'
CHECK_GROUP = 'check_group'
CHECK_PERM = 'check_perm'
CHECK_ATTRS = 'check_attrs'
CHECK_MTIME = 'check_mtime'
CHECK_INODE = 'check_inode'
CHECK_TYPE = 'check_type'

REQUIRED_ATTRIBUTES = {
    CHECK_SHA1SUM: 'hash_sha1',
    CHECK_MD5SUM: 'hash_md5',
    CHECK_SHA256SUM: 'hash_sha256',
    CHECK_SIZE: 'size',
    CHECK_OWNER: ['uid', 'user_name'],
    CHECK_GROUP: ['gid', 'group_name'],
    CHECK_PERM: 'perm',
    CHECK_ATTRS: 'attributes',
    CHECK_MTIME: 'mtime',
    CHECK_INODE: 'inode',
    CHECK_ALL: {CHECK_SHA256SUM, CHECK_SHA1SUM, CHECK_MD5SUM, CHECK_SIZE, CHECK_OWNER,
                CHECK_GROUP, CHECK_PERM, CHECK_ATTRS, CHECK_MTIME, CHECK_INODE},
    CHECK_SUM: {CHECK_SHA1SUM, CHECK_SHA256SUM, CHECK_MD5SUM}
}

REQUIRED_REG_KEY_ATTRIBUTES = {
    CHECK_OWNER: ['uid', 'user_name'],
    CHECK_GROUP: ['gid', 'group_name'],
    CHECK_PERM: 'perm',
    CHECK_MTIME: 'mtime',
    CHECK_ALL: {CHECK_OWNER, CHECK_GROUP, CHECK_PERM, CHECK_MTIME}
}

REQUIRED_REG_VALUE_ATTRIBUTES = {
    CHECK_SHA1SUM: 'hash_sha1',
    CHECK_MD5SUM: 'hash_md5',
    CHECK_SHA256SUM: 'hash_sha256',
    CHECK_SIZE: 'size',
    CHECK_TYPE: 'value_type',
    CHECK_ALL: {CHECK_SHA256SUM, CHECK_SHA1SUM, CHECK_MD5SUM, CHECK_SIZE, CHECK_TYPE},
    CHECK_SUM: {CHECK_SHA1SUM, CHECK_SHA256SUM, CHECK_MD5SUM}
}

# Key variables
MONITORED_KEY = 'SOFTWARE\\random_key'
MONITORED_KEY_2 = 'SOFTWARE\\Classes\\random_key_2'
MONITORED_KEY_3 = 'SOFTWARE\\Classes\\random_key_3'

WINDOWS_HKEY_LOCAL_MACHINE = 'HKEY_LOCAL_MACHINE'
WINDOWS_REGISTRY = 'WINDOWS_REGISTRY'


# Value key
SYNC_INTERVAL = 'SYNC_INTERVAL'
SYNC_INTERVAL_VALUE = 30
MAX_EVENTS_VALUE = 20


# Folders variables
TEST_DIR_1 = 'testdir1'
TEST_DIRECTORIES = 'TEST_DIRECTORIES'
TEST_REGISTRIES = 'TEST_REGISTRIES'

MONITORED_DIR_1 = os.path.join(PREFIX, TEST_DIR_1)

# Syscheck attributes
REPORT_CHANGES = 'report_changes'
FILE_SIZE_ENABLED = 'FILE_SIZE_ENABLED'
FILE_SIZE_LIMIT = 'FILE_SIZE_LIMIT'
DISK_QUOTA_ENABLED = 'DISK_QUOTA_ENABLED'
DISK_QUOTA_LIMIT = 'DISK_QUOTA_LIMIT'
DIFF_SIZE_LIMIT = 'diff_size_limit'

# Syscheck values
DIFF_LIMIT_VALUE = 2
DIFF_DEFAULT_LIMIT_VALUE = 51200


# FIM modes
SCHEDULED_MODE = 'scheduled'
REALTIME_MODE = 'realtime'
WHODATA_MODE = 'whodata'


# Yaml Configuration
YAML_CONF_REGISTRY_RESPONSE = 'wazuh_conf_registry_responses_win32.yaml'
YAML_CONF_SYNC_WIN32 = 'wazuh_sync_conf_win32.yaml'
YAML_CONF_MAX_EPS_SYNC = 'wazuh_sync_conf_max_eps.yaml'


# Synchronization options
SYNCHRONIZATION_ENABLED = 'SYNCHRONIZATION_ENABLED'
SYNCHRONIZATION_REGISTRY_ENABLED = 'SYNCHRONIZATION_REGISTRY_ENABLED'

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
