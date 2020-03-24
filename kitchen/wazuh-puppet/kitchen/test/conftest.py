import functools
import os
import pytest
import testinfra
 
test_host = testinfra.get_host('paramiko://{KITCHEN_USERNAME}@{KITCHEN_HOSTNAME}:{KITCHEN_PORT}'.format(**os.environ), ssh_identity_file=os.environ.get('KITCHEN_SSH_KEY'))
 
@pytest.fixture
def host():
    return test_host

@pytest.fixture
def get_wazuh_version():
    version_file_content = str(test_host.file('/tmp/kitchen/modules/wazuh/VERSION').content_string)

    wazuh_version = version_file_content.split("\n")[0] # WAZUH-PUPPET_VERSION="vX.XX.X"
    wazuh_version = wazuh_version.replace('"', '') # Remove double quote.
    wazuh_version = wazuh_version.split("v",1)[1] # Get string after 'v' : X.XX.X 
    
    return wazuh_version.rstrip()
