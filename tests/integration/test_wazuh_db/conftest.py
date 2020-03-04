import os

import pytest

from wazuh_testing.tools import WAZUH_LOGS_PATH, QUEUE_DB_PATH
from wazuh_testing.tools.monitoring import QueueMonitor, ManInTheMiddle
from wazuh_testing.tools.services import control_service, check_daemon_status


def remove_logs():
    for root, dirs, files in os.walk(WAZUH_LOGS_PATH):
        for file in files:
            os.remove(os.path.join(root, file))


def delete_dbs():
    for root, dirs, files in os.walk(QUEUE_DB_PATH):
        for file in files:
            os.remove(os.path.join(root, file))


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
