# Arrangements script
# This script creates the environment needed to make the test
import os
import shutil
import subprocess
import pytest
import time

from datetime import timedelta
from wazuh_testing.fim import WAZUH_CONF_PATH, LOG_FILE_PATH, \
    ALERTS_FILE_PATH, is_fim_scan_ended, load_fim_alerts
from wazuh_testing.tools import truncate_file, wait_for_condition, \
    get_ossec_conf, set_ossec_conf, TimeMachine, TestEnvironment

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
testdir1 = os.path.join('/', 'testdir1')
testdir2 = os.path.join('/', 'testdir2')

environments = [{'section': 'syscheck',
                 'new_values': [{'disabled': 'no'},
                                {'directories': '/testdir1,/testdir2,/noexists'}],
                 'new_attributes': [{'directories': [{'check_all': 'yes'}]}],
                 'checks': []},
                {'section': 'syscheck',
                 'new_values': [{'disabled': 'no'},
                                {'frequency': '21600'},
                                {'directories': '/testdir1,/testdir2,/noexists'}],
                 'new_attributes': [{'directories': [{'check_all': 'yes'}]}],
                 'checks': []}
                ]
# functions

def restart_wazuh():
    truncate_file(LOG_FILE_PATH)
    p = subprocess.Popen(["service", "wazuh-manager", "restart"])
    p.wait()
    wait_for_condition(lambda: is_fim_scan_ended() > -1, timeout=60)
    time.sleep(11)


# fixtures

@pytest.fixture(scope='module', params=environments)
def configure_environment(request):
    """Configure a custom environment for testing.

    :param params: List with values to customize Wazuh configuration
    """
    print(f"Setting a custom environment: {str(request.param)}")

    # save current configuration
    backup_conf = get_ossec_conf()
    test_environment = TestEnvironment(request.param.get('section'),
                                       request.param.get('new_values'),
                                       request.param.get('new_attributes'),
                                       request.param.get('checks')
                                       )
    # set new configuration
    test_environment.set_new_wazuh_conf()
    # Create test folders
    os.mkdir(testdir1)
    os.mkdir(testdir2)
    yield
    # Remove created folders
    shutil.rmtree(testdir1)
    shutil.rmtree(testdir2)
    # restore previous configuration
    set_ossec_conf(backup_conf)
    restart_wazuh()

# tests

@pytest.mark.parametrize('folder, filename, mode, content', [
    (testdir1, 'testfile', 'w', "Sample content"),
    (testdir1, 'btestfile', 'wb', b"Sample content"),
    (testdir2, 'testfile', 'w', ""),
    (testdir2, "btestfile", "wb", b"")
])
def test_regular_file(folder, filename, mode, content, configure_environment):
    """Checks if a regular file creation is detected by syscheck"""
    # Create text files
    with open(os.path.join(folder, filename), mode) as f:
        f.write(content)

    # Go ahead in time to let syscheck perform a new scan
    TimeMachine.travel_to_future(timedelta(hours=13))

    # Wait for FIM scan to finish
    wait_for_condition(lambda: is_fim_scan_ended() > -1, timeout=60)
    time.sleep(11)
    # Wait until alerts are generated
    wait_for_condition(lambda: len(load_fim_alerts(n_last=1)) == 1, timeout=5)

    truncate_file(ALERTS_FILE_PATH)
