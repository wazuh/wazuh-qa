import os
import re

import pytest

from wazuh_testing.cluster import FERNET_KEY, cluster_msg_build
from wazuh_testing.tools import WAZUH_PATH, CLUSTER_LOGS_PATH
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.monitoring import ManInTheMiddle

# Marks

pytestmark = [pytest.mark.linux, pytest.mark.tier(level=0)]

# Configurations

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'manager_conf.yaml')
params = [{'FERNET_KEY': FERNET_KEY}]
metadata = [{'fernet_key': FERNET_KEY}]
configurations = load_wazuh_configurations(configurations_path, __name__, params=params, metadata=metadata)

