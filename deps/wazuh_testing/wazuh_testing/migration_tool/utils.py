'''
Copyright (C) 2015-2022, Wazuh Inc.
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
from wazuh_testing.migration_tool import BINARY_PATH, CVE5_SCHEMA_PATH,DELTA_SCHEMA_PATH, REPORT_ERROR_MESSAGE, \
                                         SNAPSHOTS_DIR, DOWNLOADS_DIR
from wazuh_testing.tools.file import delete_file, read_json_file
from wazuh_testing.tools.logging import Logging

logger = Logging('migration_tool')


def run_content_migration_tool(args):
    """Run the Content Migration Tool with specified parameters and get the output.
    Args:
        args (str): Arguments to be passed to the tool.
    Returns:
        out (str): Result of the tool execution if no error was thrown.
        err (str): Error output if the execution fails.
    """
    cmd = ' '.join([BINARY_PATH, args])
    proc = sbp.Popen(cmd, shell=True, stdout=sbp.PIPE, stderr=sbp.PIPE)
    out, err = proc.communicate()

    out = out.decode()
    err = None
    if REPORT_ERROR_MESSAGE in out:
        err = out
        out = None

    return out, err


def sanitize_configuration(configuration):
    """Sanitize the tool configuration.
    Args:
        configuration (list): Test case configuration to be sanitized.
    Returns:
        configuration (list): Configuration sanitized.
    """
    for configurations_obj in configuration:
        configurations_list = configurations_obj['configurations']
        for config_obj in configurations_list:
            for key in config_obj:
                config_obj[key.lower()] = config_obj.pop(key)

    return configuration


def validate_json_against_schema(json_document, schema):
    """Validate a JSON document under the given schema.
    Args:
        json_document (str): Path of the JSON document to be validated
        schema (str): Path of the CVE5 Schema by default.
    Returns:
        result (bool): False if the validation thrown an error, True if not.
        error (str): Error in the JSON document.
    """
    schema = read_json_file(schema)

    try:
        validate(instance=json_document, schema=schema)
    except ValidationError as err:
        return False, err.message

    return True, ''


def validate_against_delta_schema(_elements):
    """Wrapper function
    """
    _result = True
    _errors = []
    for cve in _elements:
        _result, _error = validate_json_against_schema(cve, DELTA_SCHEMA_PATH)
        if _result is False:
            _errors.append(_error)

    return _errors


def validate_against_cve5_schema(_elements):
    """Wrapper function
    """
    _result = True
    _errors = []

    for cves in _elements:
        data = json.loads(cves['data_blob'])
        _result, _error = validate_json_against_schema(data, CVE5_SCHEMA_PATH)
        if _result is False:
            _errors.append(_error)

    return _errors


def query_publisher_db(query):
    """Function to query the DB created by Content Migration Tool.
    Args:
        query (str): Query to send to the DB.
    Returns:
        result (list): Query results, empty if no query was executed or no results were returned.
    """
    result = []

    try:
        cnx = mysql.connector.connect(
            host="localhost",
            user="test",
            password="Test123$",
            database="test_database"
            )
    except mysql.connector.Error as err:
        cnx = None
        if err.errno == errorcode.ER_ACCESS_DENIED_ERROR:
            logger.error("Something is wrong with your user name or password")
        elif err.errno == errorcode.ER_BAD_DB_ERROR:
            logger.error("Database does not exist")
        else:
            logger.error(err)

    if cnx is not None:
        cursor = cnx.cursor()
        cursor.execute(query)
        result = cursor.fetchall()
        cnx.close()

    return result


def clean_migration_tool_output_files():
    """Remove all files generated by Content Migration Tool.
    """

    def remove_files_in_folder(folders_list):
        for folder in folders_list:
            files = glob.glob(os.path.join(folder, '*'))
            for file in files:
                delete_file(file)

    snaptshots_folders = glob.glob(os.path.join(SNAPSHOTS_DIR, '*'))
    downloads_folders = glob.glob(os.path.join(DOWNLOADS_DIR, '*'))

    remove_files_in_folder(snaptshots_folders)
    remove_files_in_folder(downloads_folders)


def drop_migration_tool_tables():
    """Remove the tables created by CMT.
    """
    tables = query_publisher_db('SHOW tables;')
    for table in tables:
        # `table` is a tuple with 1 element, so this one is selected
        query_publisher_db(f"DROP TABLE {table[0]};")


def remove_status_file(vendor):
    """Remove the status file to avoid the migration to be skipped.

    Args:
        vendor (str): Name of the vendor.
    """
    status_file = os.path.join(DOWNLOADS_DIR, vendor, f"{vendor}_status.json")
    delete_file(status_file)
