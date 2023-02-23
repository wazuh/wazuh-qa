'''
copyright: Copyright (C) 2015-2023, Wazuh Inc.
           Created by Wazuh, Inc. <info@wazuh.com>.
           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
'''
SYSCOLLECTOR_PREFIX = ".+wazuh-modulesd:syscollector.+"

# Callback messages
CB_MODULE_STARTING = 'DEBUG: Starting Syscollector.'
CB_MODULE_STARTED = 'INFO: Module started.'
CB_SCAN_STARTED = 'INFO: Starting evaluation.'
CB_SCAN_FINISHED = 'INFO: Evaluation finished.'
CB_SYNC_STARTED = 'DEBUG: Starting syscollector sync'
CB_SYNC_FINISHED = 'DEBUG: Ending syscollector sync'
CB_SYSCOLLECTOR_DISABLED = 'INFO: Module disabled. Exiting...'
CB_HARDWARE_SCAN_STARTED = 'DEBUG: Starting hardware scan'
CB_HARDWARE_SCAN_FINISHED = 'DEBUG: Ending hardware scan'
CB_OS_SCAN_STARTED = 'DEBUG: Starting os scan'
CB_OS_SCAN_FINISHED = 'DEBUG: Ending os scan'
CB_NETWORK_SCAN_STARTED = 'DEBUG: Starting network scan'
CB_NETWORK_SCAN_FINISHED = 'DEBUG: Ending network scan'
CB_PACKAGES_SCAN_STARTED = 'DEBUG: Starting packages scan'
CB_PACKAGES_SCAN_FINISHED = 'DEBUG: Ending packages scan'
CB_PORTS_SCAN_STARTED = 'DEBUG: Starting ports scan'
CB_PORTS_SCAN_FINISHED = 'DEBUG: Ending ports scan'
CB_PROCESES_SCAN_STARTED = 'DEBUG: Starting processes scan'
CB_PROCESES_SCAN_FINISHED = 'DEBUG: Ending processes scan'
CB_HOTFIXES_SCAN_STARTED = 'DEBUG: Starting hotfixes scan'
CB_HOTFIXES_SCAN_FINISHED = 'DEBUG: Ending hotfixes scan'
