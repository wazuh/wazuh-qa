import pytest
import yaml
from wazuh_testing.tools import LOG_FILE_PATH
from wazuh_testing.tools.monitoring import FileMonitor

def load_tests(path):
    """ Loads a yaml file from a path 
    Retrun 
    ----------
    yaml structure
    """
    with open(path) as f:
        return yaml.safe_load(f)

@pytest.fixture(scope='module')
def wait_for_agentd_startup(request):
    """Wait until agentd has begun"""
    def callback_agentd_startup(line):
        if 'Accepting connections on port 1515' in line:
            return line
        return None

    log_monitor = FileMonitor(LOG_FILE_PATH)
    log_monitor.start(timeout=30, callback=callback_agentd_startup)