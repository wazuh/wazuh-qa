'''
Copyright (C) 2015-2022, Wazuh Inc.
Created by Wazuh, Inc. <info@wazuh.com>.
This program is free software; you can redistribute it and/or modify it under the terms
'''
import os


# Useful variables
WORKING_DIR = '/var/wazuh'
OUTPUT_DIR = f"{WORKING_DIR}/incoming"
CVE5_SCHEMA_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'CVE_JSON_5.0_bundled.json')
DELTA_SCHEMA_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'delta_schema.json')
BINARY_PATH = f"{WORKING_DIR}/bin/content_migration"
SNAPSHOTS_DIR = f"{WORKING_DIR}/incoming/snapshots/"
DOWNLOADS_DIR = f"{WORKING_DIR}/incoming/downloads/"
LOG_FILE_PATH = f"{WORKING_DIR}/logs/content_migration.log"

# Callback messages
CB_PROCESS_STARTED = r'.+\[info\]\[Orchestrator - start\]: Starting process'
CB_FETCHING_STAGE_INITIALIZED = r'.+\[info\].+handleRequest\]: Starting fetch of .+'
CB_FETCHING_STAGE_FINISHED = r'.+\[info\].+fetch\]: Download done successfully'
CB_DECOMPRESSION_STAGE_INITIALIZED = r'.+\[info\].+handleRequest\]: Starting decompression of .+'
CB_PARSER_STAGE_INITIALIZED = r'.+\[info\].+Parser - handleRequest\]: Starting parse of .+'
CB_NORMALIZER_STAGE_INITIALIZED = r'.+\[info\]\[Normalizer.+ - handleRequest]: Starting process'
CB_DIFF_STAGE_INITIALIZED = r'.+\[info\]\[DiffEngine.+ - handleRequest\]: Starting process'
CB_DIFF_STAGE_FINISHED = r'.+\[info\]\[DiffEngine.+ - diffData\]: Created last snapshot: /var/wazuh/incoming/'
CB_PUBLISHER_STAGE_INITIALIZED = r'.+\[info\]\[DiffPublisher - handleRequest\]: Starting process. Configuration:'
CB_PROCESS_COMPLETED = r'.+Migration process completed successfully!'
REPORT_ERROR_MESSAGE = r'Remote exited with error'
