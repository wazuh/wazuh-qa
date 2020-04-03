# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import pytest

from wazuh_testing.cluster import callback_detect_worker_connected, callback_detect_master_serving, cluster_msg_build


@pytest.fixture(scope='module')
def detect_initial_worker_connected(request):
    """Detect worker node is connected to master after restarting clusterd"""
    cluster_log_monitor = getattr(request.module, 'log_monitors')[0]
    cluster_log_monitor.start(timeout=5, callback=callback_detect_worker_connected)


@pytest.fixture(scope='module')
def detect_initial_master_serving(request):
    """Detect master node is serving after restarting clusterd"""
    cluster_log_monitor = getattr(request.module, 'log_monitors')[0]
    cluster_log_monitor.start(timeout=5, callback=callback_detect_master_serving)


@pytest.fixture(scope='module')
def send_initial_worker_hello(connect_to_sockets_module):
    """Send initial hello to master"""
    message = cluster_msg_build(cmd=b'hello', counter=0, payload=b'worker1 wazuh worker 3.12', encrypt=True)
    connect_to_sockets_module[0].send(message)
    connect_to_sockets_module[0].receive()
