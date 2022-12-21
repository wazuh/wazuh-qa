'''
Copyright (C) 2015-2022, Wazuh Inc.
Created by Wazuh, Inc. <info@wazuh.com>.
This program is free software; you can redistribute it and/or modify it under the terms
'''
import os


# Useful varibles
WORKING_DIR = '/var/wazuh'
OUTPUT_DIR = f"{WORKING_DIR}/incoming"
CVE5_SCHEMA_PATH = f"{WORKING_DIR}/config/cve5/CVE_JSON_5.0_schema.json"
DELTA_SCHEMA_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'delta_schema.json')
BINARY_PATH = f"{WORKING_DIR}/bin/content_migration"
SNAPSHOTS_DIR = f"{WORKING_DIR}/incoming/snapshots/"
DOWNLOADS_DIR = f"{WORKING_DIR}/incoming/downloads/"
LOG_FILE_PATH = f"{WORKING_DIR}/logs/content_migration.log"

# Callback messages
CB_PROCESS_COMPLETED = '.+Migration process completed successfully'
REPORT_ERROR_MESSAGE = 'Remote exited with error'