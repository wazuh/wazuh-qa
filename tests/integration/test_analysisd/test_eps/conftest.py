# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import pytest

from wazuh_testing.tools import configuration


@pytest.fixture(scope='function')
def configure_analysisd_one_thread():
    """Fixture to configure the local internal options file to work with one thread."""
    local_internal_options = {'analysisd.event_threads': '1', 'analysisd.syscheck_threads': '1',
                              'analysisd.syscollector_threads': '1', 'analysisd.rootcheck_threads': '1',
                              'analysisd.sca_threads': '1', 'analysisd.hostinfo_threads': '1',
                              'analysisd.winevt_threads': '1', 'analysisd.rule_matching_threads': '1',
                              'analysisd.dbsync_threads': '1', 'remoted.worker_pool': '1'}

    # Backup the old local internal options
    backup_local_internal_options = configuration.get_wazuh_local_internal_options()

    # Add the new configuration to local internal options
    configuration.add_wazuh_local_internal_options(local_internal_options)

    yield

    # Backup the old local internal options cofiguration
    configuration.set_wazuh_local_internal_options(backup_local_internal_options)
