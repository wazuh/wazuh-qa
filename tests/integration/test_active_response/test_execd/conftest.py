import os
import platform
import pytest

import wazuh_testing.execd as execd
from wazuh_testing.tools import WAZUH_PATH, get_version


@pytest.fixture(scope="session")
def set_ar_conf_mode():
    """Configure Active Responses used in tests."""
    folder = 'shared' if platform.system() == 'Windows' else 'etc/shared'
    local_int_conf_path = os.path.join(WAZUH_PATH, folder, 'ar.conf')
    debug_line = "restart-wazuh0 - restart-wazuh - 0\nrestart-wazuh0 - restart-wazuh.exe - 0\n" \
                 "firewall-drop0 - firewall-drop - 0\nfirewall-drop5 - firewall-drop - 5\n"
    with open(local_int_conf_path, 'w') as local_file_write:
        local_file_write.write(debug_line)
    with open(local_int_conf_path, 'r') as local_file_read:
        lines = local_file_read.readlines()
        for line in lines:
            if line == debug_line:
                return


@pytest.fixture(scope="session")
def set_debug_mode():
    """Set execd daemon in debug mode."""
    folder = '' if platform.system() == 'Windows' else 'etc'
    local_int_conf_path = os.path.join(WAZUH_PATH, folder, 'local_internal_options.conf')
    debug_line = 'windows.debug=2\n' if platform.system() == 'Windows' else 'execd.debug=2\n'
    with open(local_int_conf_path) as local_file_read:
        lines = local_file_read.readlines()
        for line in lines:
            if line == debug_line:
                return
    with open(local_int_conf_path, 'a') as local_file_write:
        local_file_write.write('\n'+debug_line)


@pytest.fixture(scope="session")
def test_version():
    """Validate Wazuh version."""
    if get_version() < "v4.2.0":
        raise AssertionError("The version of the agent is < 4.2.0")


@pytest.fixture
def truncate_ar_log():
    """Truncate the logs related with Active Response."""
    execd.clean_logs()

    yield

    execd.clean_logs()
