# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import pytest

from wazuh_testing.tools.monitoring import ManInTheMiddle, QueueMonitor
from wazuh_testing.tools.services import control_service, check_daemon_status, remove_logs, delete_dbs


@pytest.fixture(scope='module')
def configure_mitm_environment_wazuhdb(request):
    """Use MITM to replace analysisd and wazuh-db sockets."""
    wdb_path = getattr(request.module, 'wdb_path')

    # Stop wazuh-service and ensure all daemons are stopped
    control_service('stop')
    check_daemon_status(running=False)
    remove_logs()

    control_service('start', daemon='wazuh-db', debug_mode=True)
    check_daemon_status(running=True, daemon='wazuh-db')

    mitm_wdb = ManInTheMiddle(socket_path=wdb_path)
    wdb_queue = mitm_wdb.queue
    mitm_wdb.start()

    wdb_monitor = QueueMonitor(queue_item=wdb_queue)

    setattr(request.module, 'wdb_monitor', wdb_monitor)

    yield

    mitm_wdb.shutdown()

    for daemon in ['wazuh-db']:
        control_service('stop', daemon=daemon)
        check_daemon_status(running=False, daemon=daemon)

    # Delete all db
    delete_dbs()

    control_service('start')
