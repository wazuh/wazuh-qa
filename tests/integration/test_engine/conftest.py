# Copyright (C) 2015-2023, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import os
import pytest

from wazuh_testing import processes
from wazuh_testing.modules import engine
from wazuh_testing.tools.file import truncate_file
from wazuh_testing.tools.services import control_service


KVDBS_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data', 'kvdbs')


@pytest.fixture()
def restart_engine_function():
    """Start the wazuh-engine daemon before running a test, and stop it when finished."""
    control_service('restart', daemon=engine.MODULE_NAME)

    yield

    control_service('stop', daemon=engine.MODULE_NAME)


@pytest.fixture()
def truncate_engine_files():
    """Truncate all the log files and json alerts files before and after the test execution."""
    log_files = [engine.ENGINE_ALERTS_PATH, engine.ENGINE_LOG_PATH]

    for log_file in log_files:
        truncate_file(log_file)

    yield

    for log_file in log_files:
        truncate_file(log_file)


@pytest.fixture()
def create_predefined_kvdb(kvdb_names):
    """Create a kvdb with the provided info.

    Args:
        kvdb_names(list): Names that indentify the predefined kvdbs stored in the engine's module.
    """
    for kvdb_name in kvdb_names:
        kvdb_json_file = os.path.join(KVDBS_PATH, f"{kvdb_name}.json")
        processes.run_local_command_printing_output(engine.create_api_call('kvdb', 'create',
                                                                           {'-n': kvdb_name, '-p': kvdb_json_file}))


@pytest.fixture()
def clean_stored_kvdb(kvdb_names):
    """Remove the kvdb stored on memory.

    During the setup, all the dbs will be deleted. But in the tierdown, the created within the testing will be deleted.

    Args:
        kvdb_names(list): Names that indentify the predefined kvdbs stored in the engine's module.
    """
    already_existing_kvdb_names = engine.get_available_kvdbs()

    # Delete the already existing kvdbs to clean the env
    for kvdb_name in already_existing_kvdb_names:
        processes.run_local_command_printing_output(engine.create_api_call('kvdb', 'delete', {'-n': kvdb_name}))

    yield

    # Delete the databases created during the testing
    for kvdb_name in kvdb_names:
        processes.run_local_command_printing_output(engine.create_api_call('kvdb', 'delete', {'-n': kvdb_name}))


@pytest.fixture()
def clean_all_stored_kvdb():
    """Remove all the kvdbs stored on memory."""

    # Get the currently loaded kvdbs within the defined kvdb's path
    already_existing_kvdb_names = engine.get_available_kvdbs()

    for kvdb_name in already_existing_kvdb_names:
        processes.run_local_command_printing_output(engine.create_api_call('kvdb', 'delete', {'-n': kvdb_name}))

    yield

    for kvdb_name in already_existing_kvdb_names:
        processes.run_local_command_printing_output(engine.create_api_call('kvdb', 'delete', {'-n': kvdb_name}))
