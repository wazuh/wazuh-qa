# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

'''
The purpose of this file is to contain all the variables necessary for FIM in order to be easier to maintain if one of them changes in the future
'''

# variables

# key variables
WINDOWS_HKEY_LOCAL_MACHINE = "HKEY_LOCAL_MACHINE"
MONITORED_KEY = "SOFTWARE\\random_key"
WINDOWS_REGISTRY = 'WINDOWS_REGISTRY'


# value key
SYNC_INTERVAL = 'SYNC_INTERVAL'
SYNC_INTERVAL_VALUE = MAX_EVENTS_VALUE = 20


# FIM modules
SCHEDULE_MODE = 'scheduled'