# Copyright (C) 2015-2022, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import pytest


@pytest.fixture(scope='function')
def set_wazuh_configuration_analysisd(configuration, set_wazuh_configuration):
    """Set wazuh configuration
    Args:
        configuration (dict): Configuration template data to write in the ossec.conf.
        set_wazuh_configuration (fixture): Set the wazuh configuration according to the configuration data.
    """
    yield
