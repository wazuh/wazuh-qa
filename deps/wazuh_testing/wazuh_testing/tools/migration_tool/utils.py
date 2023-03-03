'''
Copyright (C) 2015-2023, Wazuh Inc.
Created by Wazuh, Inc. <info@wazuh.com>.
This program is free software; you can redistribute it and/or modify it under the terms
'''
import glob
import json
import os
import subprocess as sbp

import mysql.connector
from jsonschema import validate
from jsonschema.exceptions import ValidationError
from mysql.connector import errorcode
from wazuh_testing.tools.migration_tool import MIGRATION_TOOL_PATH, CVE5_SCHEMA_PATH, DELTA_SCHEMA_PATH, \
                                               ERROR_MESSAGES, SNAPSHOTS_DIR, DOWNLOADS_DIR, MIGRATION_TOOL_LOG_PATH, \
                                               MYSQL_CREDENTIALS, UNCOMPRESSED_DIR
from wazuh_testing.tools.file import delete_all_files_in_folder, read_json_file, truncate_file
from wazuh_testing.tools.logging import Logging

logger = Logging('migration_tool')


def run_content_migration_tool(args='', config_files=None):
    '''Run the Content Migration Tool with specified parameters and get the output.

    Args:
        args (str): Arguments to be passed to the tool. For instance: '--debug' or '-w /tmp/workdir'
        config_files (list): List of configuration files to be executed.
    Returns:
        output (str): Result of the tool execution if no error was thrown.
        errors (str): Error output if the execution fails.
    '''
    errors = ''

    def run_tool(cmd):
        proc = sbp.Popen(cmd, shell=True, stdout=sbp.PIPE, stderr=sbp.PIPE)
        out, err = proc.communicate()

        return out, err

    for file_path in config_files:
        truncate_file(MIGRATION_TOOL_LOG_PATH)
        command = ' '.join([MIGRATION_TOOL_PATH, '-i', file_path, args])
        output, _ = run_tool(command)
        output = output.decode()
        error_checker = [True for msg in ERROR_MESSAGES if msg in output]
        if len(error_checker) > 0:
            errors += f"\n{output}"

    return output, errors


def get_latest_delta_file(deltas_filepath):
    '''Select the newest delta file generated (where the results are) from the list of all files.

    Args:
        deltas_filepath (str): Path where the files are located.
    Returns:
        newest_file (str): Path of the newest file.
    '''
    all_files = glob.glob(os.path.join(deltas_filepath, '*.delta.*'))
    newest_file = max(all_files, key=os.path.getctime)

    return newest_file


def sanitize_configuration(configuration):
    '''Normalize the configuration for it to be correctly processed and compatible.

    Args:
        configuration (list): Test case configuration to be sanitized.
    Returns:
        configuration (list): Configuration normalized.
    '''
    for configurations_obj in configuration:
        configurations_list = configurations_obj['configurations']
        for config_obj in configurations_list:
            for key in config_obj:
                config_obj[key.lower()] = config_obj.pop(key)

    return configuration


def validate_json_against_schema(json_document, schema):
    '''Validate a JSON document under the given schema.

    Args:
        json_document (str): Path of the JSON document to be validated
        schema (str): Path of the CVE5 Schema by default.
    Returns:
        result (bool): False if the validation thrown an error, True if not.
        error (str): Error in the JSON document.
    '''
    schema = read_json_file(schema)

    try:
        validate(instance=json_document, schema=schema)
    except ValidationError as err:
        return False, err.message

    return True, ''


def validate_against_delta_schema(_elements):
    '''Wrapper function. Validate a file with deltas under the Delta schema.

    Args:
        _elements (dict): Python dictionary containing the data to be validated against the Delta schema.
    '''
    _result = True
    _errors = []
    for cve in _elements:
        _result, _error = validate_json_against_schema(cve, DELTA_SCHEMA_PATH)
        if _result is False:
            _errors.append(_error)

    return _errors


def validate_against_cve5_schema(_elements):
    '''Wrapper function. Validate a file with deltas under the CVE5 schema.

    Args:
        _elements (dict): Python dictionary containing the data to be validated against the CVE5 schema.
    '''
    _result = True
    _errors = []

    for cves in _elements:
        data = json.loads(cves['data_blob'])
        _result, _error = validate_json_against_schema(data, CVE5_SCHEMA_PATH)
        if _result is False:
            _errors.append(_error)

    return _errors


def query_publisher_db(query):
    '''Function to query the DB created by Content Migration Tool.
    Args:
        query (str): Query to send to the DB.
    Returns:
        result (list): Query results, empty if no query was executed or no results were returned.
    '''
    result = []

    try:
        connection = mysql.connector.connect(
            host=MYSQL_CREDENTIALS['host'],
            user=MYSQL_CREDENTIALS['user'],
            password=MYSQL_CREDENTIALS['password'],
            database=MYSQL_CREDENTIALS['database']
            )
    except mysql.connector.Error as error:
        connection = None
        if error.errno == errorcode.ER_ACCESS_DENIED_ERROR:
            logger.error('Something is wrong with your user name or password')
        elif error.errno == errorcode.ER_BAD_DB_ERROR:
            logger.error('Database does not exist')
        else:
            logger.error(error)

    if connection is not None:
        cursor = connection.cursor()
        cursor.execute(query)
        result = cursor.fetchall()
        connection.close()

    return result


def clean_migration_tool_output_files():
    '''Remove all files generated by Content Migration Tool.
    '''
    output_folders = [SNAPSHOTS_DIR, DOWNLOADS_DIR, UNCOMPRESSED_DIR]
    vendors_folders = os.listdir(SNAPSHOTS_DIR)
    for output_folder in output_folders:
        for folder in vendors_folders:
            folder = os.path.join(output_folder, folder)
            delete_all_files_in_folder(folder)


def drop_migration_tool_tables():
    '''Remove the tables created by CMT.
    '''
    tables = query_publisher_db('SHOW tables;')
    for table in tables:
        # `table` is a tuple with 1 element, so this one is selected
        query_publisher_db(f"DROP TABLE {table[0]};")
