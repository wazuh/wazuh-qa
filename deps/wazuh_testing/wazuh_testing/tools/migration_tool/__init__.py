'''
Copyright (C) 2015-2023, Wazuh Inc.
Created by Wazuh, Inc. <info@wazuh.com>.
This program is free software; you can redistribute it and/or modify it under the terms
'''
import os


# Module variables
CVE5_SCHEMA_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'CVE_JSON_5.0_bundled.json')
DELTA_SCHEMA_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'delta_schema.json')
WORKING_DIR = '/var/wazuh'
MIGRATION_TOOL_PATH = f"{WORKING_DIR}/bin/content_migration"
MIGRATION_TOOL_OUTPUT_PATH = f"{WORKING_DIR}/output"
MIGRATION_TOOL_LOG_PATH = f"{MIGRATION_TOOL_OUTPUT_PATH}/logs/temp_configuration_file.log"
GENERATED_FILES_DIR = f"{MIGRATION_TOOL_OUTPUT_PATH}/migration"
SNAPSHOTS_DIR = f"{GENERATED_FILES_DIR}/snapshots"
DOWNLOADS_DIR = f"{GENERATED_FILES_DIR}/downloads"
UNCOMPRESSED_DIR = f"{GENERATED_FILES_DIR}/uncompressed"
ENVIRONMENT_CONFIG = None

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
CB_STAGES = [
    CB_PROCESS_STARTED, CB_FETCHING_STAGE_INITIALIZED, CB_FETCHING_STAGE_FINISHED, CB_DECOMPRESSION_STAGE_INITIALIZED,
    CB_PARSER_STAGE_INITIALIZED, CB_NORMALIZER_STAGE_INITIALIZED, CB_DIFF_STAGE_INITIALIZED, CB_DIFF_STAGE_FINISHED,
    CB_PUBLISHER_STAGE_INITIALIZED, CB_PROCESS_COMPLETED
]
CB_MIGRATION_SKIPPED = r'.+\[info\]\[MigrationStatusCheck.+\]: File already migrated. Stopping migration process.'
CB_REPORT_ERROR_MESSAGE = r'Remote exited with error'
CB_INVALID_CONFIG_MESSAGE = r'No valid configuration file was found at'
ERROR_MESSAGES = [CB_REPORT_ERROR_MESSAGE, CB_INVALID_CONFIG_MESSAGE]
