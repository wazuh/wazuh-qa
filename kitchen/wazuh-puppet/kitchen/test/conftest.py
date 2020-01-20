import functools
import os
import pytest
import testinfra
import subprocess
 
test_host = testinfra.get_host('paramiko://{KITCHEN_USERNAME}@{KITCHEN_HOSTNAME}:{KITCHEN_PORT}'.format(**os.environ), ssh_identity_file=os.environ.get('KITCHEN_SSH_KEY'))
 
@pytest.fixture
def host():
    return test_host

@pytest.fixture
def get_wazuh_version():
    version_file_content = str(test_host.file('/tmp/kitchen/modules/wazuh/VERSION').content_string)
    aux_text_file = open("VERSION.txt", "w")
    aux_text_file.write(version_file_content)
    aux_text_file.close()
    wazuh_version = subprocess.getoutput("cat VERSION.txt | grep \"WAZUH-PUPPET_VERSION=\" | cut -d '=' -f 2 | tr -d '\"' | tr -d 'v'")

    return str(wazuh_version)
