
import os
import pytest
import yaml

from wazuh_testing.tools import WAZUH_API_CONF


@pytest.fixture(scope='module')
def set_default_api_conf(request):
    hm = getattr(request.module, 'host_manager')
    new_api_conf = getattr(request.module, 'default_api_conf')
    test_hosts = getattr(request.module, 'test_hosts')
    api_tmp_backup = 'api_backup_tmp.yaml'
    api_conf_backup = dict()
    for host in test_hosts:
        api_conf_backup[host] = yaml.safe_load(hm.get_file_content(host, WAZUH_API_CONF))

    with open(api_tmp_backup, 'w') as f:
        f.write(yaml.safe_dump(api_conf_backup))

    hm.apply_api_config(api_config=new_api_conf, clear_log=True)

    yield

    hm.apply_api_config(api_config=api_tmp_backup)
    os.remove(api_tmp_backup)
