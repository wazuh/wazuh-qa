'''
Copyright (C) 2015-2022, Wazuh Inc.
Created by Wazuh, Inc. <info@wazuh.com>.
This program is free software; you can redistribute it and/or modify it under the terms
'''
import os
import shutil
import subprocess as sbp

import mysql.connector
from mysql.connector import errorcode
from jsonschema import validate
from jsonschema.exceptions import ValidationError
from wazuh_testing.tools.file import read_json_file
from wazuh_testing.tools.logging import Logging
from wazuh_testing.event_monitor import check_event


VENDORS = ['arch', 'alas', 'redhat', 'almalinux', 'canonical', 'cve', 'debian', 'nvd', 'suse']
WORKING_DIR = '/var/wazuh'
OUTPUT_DIR = f"{WORKING_DIR}/incoming"
CVE5_SCHEMA_PATH = f"{WORKING_DIR}/config/cve5/CVE_JSON_5.0_schema.json"
BINARY_PATH = f"{WORKING_DIR}/bin/content_migration"
SNAPSHOTS_DIR = f"{WORKING_DIR}/incoming/snapshots/"
LOG_FILE_PATH = f"{WORKING_DIR}/logs/content_migration.log"

logger = Logging('cmt')

# Callbacks
CB_PROCESS_COMPLETED = '.+Migration process completed successfully'


def check_process_completion():
    check_event(callback=CB_PROCESS_COMPLETED, file_to_monitor=LOG_FILE_PATH)


def run_content_migration_tool(args):
    """Run the Content Migration tool with specified parameters and get the output.

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
    if 'Remote exited with error' in out:
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


def validate_json_against_schema(json_document, schema=CVE5_SCHEMA_PATH):
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


def query_publisher_db(query):
    """Function to query the DB created by the Content Migration Tool.

    Args:
        query (str): Query to send to the DB.

    Returns:
        result (list): Query results, empty if no query was executed or no results were returned.
    """
    try:
        cnx = mysql.connector.connect(
            host="localhost",
            user="test",
            password="Test123$",
            database="test_database"
            )
    except mysql.connector.Error as err:
        cnx = None
        result = []
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


def truncate_log_file():
    """Truncate the tool log file.
    """
    with open(LOG_FILE_PATH, 'w'):
        pass


def clean_files():
    """Remove all files generated for all existing vendors.
    """
    for vendor in VENDORS:
        # Delete all generated files
        folder = os.path.join(SNAPSHOTS_DIR, vendor)
        for filename in os.listdir(folder):
            file_path = os.path.join(folder, filename)
            try:
                if os.path.isfile(file_path) or os.path.islink(file_path):
                    os.unlink(file_path)
                elif os.path.isdir(file_path):
                    shutil.rmtree(file_path)
            except Exception as err:
                print(f"Failed to delete {file_path}. Reason: {err}")


def drop_tables():
    """Remove the tables created during the migration process.
    """
    tables = query_publisher_db('SHOW tables;')
    for table in tables:
        # `table` is a tuple with 1 element, so this one is selected
        query_publisher_db(f"DROP TABLE {table[0]};")
