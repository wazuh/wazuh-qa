import functools
import os
import pytest
import testinfra
import json 
test_host = testinfra.get_host('paramiko://{KITCHEN_USERNAME}@{KITCHEN_HOSTNAME}:{KITCHEN_PORT}'.format(**os.environ), ssh_identity_file=os.environ.get('KITCHEN_SSH_KEY'))
 
@pytest.fixture
def host():
    return test_host

@pytest.fixture
def node():
    return json.loads(str(test_host.file('/tmp/kitchen_chef_node.json').content_string))