# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os

import pytest
import yaml
from wazuh_testing import global_parameters

from test_fim.test_files.test_multiple_dirs.common import multiple_dirs_test
from wazuh_testing.fim import LOG_FILE_PATH, generate_params
from wazuh_testing.tools.configuration import load_wazuh_configurations, check_apply_test
from wazuh_testing.tools.monitoring import FileMonitor
from wazuh_testing.tools import PREFIX

# Marks

pytestmark = pytest.mark.tier(level=1)

# variables

n_dirs = 64
test_directories = [os.path.join(PREFIX, f'testdir{i}') for i in range(n_dirs)]
directory_str = ','.join(test_directories)
wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'multiple_entries.yaml')


def create_yaml(n_dirs=0):
    """Create a new YAML with the required WILDCARDS for every directory in `test_directories`.

    Parameters
    ----------
    n_dirs : int, optional
        Number of created/monitored directories. Default `0`
    """
    with open(os.path.join(test_data_path, 'multiple_entries.yaml'), 'w') as f:
        dikt = [
            {
                'tags': ['multiple_dir_entries'],
                'apply_to_modules': ['test_multiple_entries'],
                'sections': [
                    {'section': 'syscheck',
                     'elements':
                        [
                            {'disabled': {'value': 'no'}},
                        ]
                     }
                ]
            }
        ]

        for new_dir in ({'directories': {'value': f'DIR{i}', 'attributes': ['FIM_MODE']}} for i in range(n_dirs)):
            dikt[0]['sections'][0]['elements'].append(new_dir)
        f.write(yaml.safe_dump(dikt, sort_keys=False))


# configurations

create_yaml(n_dirs=len(test_directories))
conf_params = {f'DIR{i}': testdir for i, testdir in enumerate(test_directories)}
conf_params['MODULE_NAME'] = __name__
p, m = generate_params(extra_params=conf_params)

configurations = load_wazuh_configurations(configurations_path, __name__, params=p, metadata=m)


# fixtures

@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# tests

@pytest.mark.parametrize('dir_list, tags_to_apply', [
    (test_directories, {'multiple_dir_entries'})
])
def test_cud_multiple_dir_entries(dir_list, tags_to_apply, get_configuration, configure_environment, restart_syscheckd,
                                  wait_for_fim_start):
    """
    Check if syscheck can detect every event when adding, modifying and deleting a file within multiple monitored
    directories.

    These directories will be added using a new entry for every one of them:
        <directories>testdir0</directories>
        ...
        <directories>testdirn</directories>

    Parameters
    ----------
    dir_list : list
        List with all the directories to be monitored.
    """
    check_apply_test(tags_to_apply, get_configuration['tags'])

    file = 'regular'
    scheduled = get_configuration['metadata']['fim_mode'] == 'scheduled'
    whodata = get_configuration['metadata']['fim_mode'] == 'whodata'

    try:
        multiple_dirs_test(mode="entries", dir_list=dir_list, file=file, scheduled=scheduled, whodata=whodata,
                           log_monitor=wazuh_log_monitor, timeout=2 * global_parameters.default_timeout)
    except TimeoutError as e:
        if whodata:
            pytest.xfail(reason='Xfailed due to issue: https://github.com/wazuh/wazuh/issues/4731')
        else:
            raise e
