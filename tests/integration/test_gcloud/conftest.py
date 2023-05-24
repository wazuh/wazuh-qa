# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import pytest

from wazuh_testing import global_parameters
from wazuh_testing.tools import WAZUH_PATH
from wazuh_testing.tools.file import write_file, remove_file
from wazuh_testing.gcloud import detect_gcp_start, publish_sync
import wazuh_testing.tools.configuration as conf


@pytest.fixture(scope='session', autouse=True)
def handle_credentials_file():
    if global_parameters.gcp_credentials is None or global_parameters.gcp_credentials_file is None:
        return

    write_file(os.path.join(WAZUH_PATH, global_parameters.gcp_credentials_file), global_parameters.gcp_credentials)
    yield
    remove_file(os.path.join(WAZUH_PATH, global_parameters.gcp_credentials_file))


@pytest.fixture(scope='session', autouse=True)
def validate_global_configuration():
    if global_parameters.gcp_project_id is None:
        raise ValueError('Google Cloud project id not found. Please use --gcp-project-id')

    if global_parameters.gcp_subscription_name is None:
        raise ValueError('Google Cloud subscription name not found. Please use --gcp-subscription-name')

    if global_parameters.gcp_credentials_file is None:
        raise ValueError('Credentials json file not found. Please enter a valid path using --gcp-credentials-file')

    if global_parameters.gcp_topic_name is None:
        raise ValueError('Gloogle Cloud topic name not found. Please enter a valid path using --gcp-topic-name')


@pytest.fixture(scope='function')
def publish_messages(request):
    publish_sync(global_parameters.gcp_project_id, global_parameters.gcp_topic_name,
                 global_parameters.gcp_credentials_file, request.param)

    return len(request.param)


@pytest.fixture(scope='module')
def wait_for_gcp_start(get_configuration, request):
    # Wait for module gpc-pubsub starts
    file_monitor = getattr(request.module, 'wazuh_log_monitor')
    detect_gcp_start(file_monitor)


@pytest.fixture(scope="session", autouse=True)
def configure_internal_options():
    local_internal_options = {'wazuh_modules.debug': 2, 'analysisd.debug': 2, 'monitord.rotate_log': 0, 'monitord.day_wait': 0, 'monitord.keep_log_days': 0,'monitord.size_rotate': 0}
    conf.set_local_internal_options_dict(local_internal_options)
    yield
    local_internal_options = {'wazuh_modules.debug': 0, 'analysisd.debug': 0, "monitord.rotate_log": 1, "monitord.day_wait": 10, "monitord.keep_log_days": 31,'monitord.size_rotate': 512}
    conf.set_local_internal_options_dict(local_internal_options)
