# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import pytest

from wazuh_testing.tools.services import control_service


@pytest.fixture(scope='package')
def restart_logcollector_required_daemons_package():
    control_service('restart', 'wazuh-agentd')
    control_service('restart', 'wazuh-logcollector')
    control_service('restart', 'wazuh-modulesd')

    yield

    control_service('restart', 'wazuh-agentd')
    control_service('restart', 'wazuh-logcollector')
    control_service('restart', 'wazuh-modulesd')
