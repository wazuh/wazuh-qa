# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import glob
import os
import re
import pytest

from wazuh_testing.fim import LOG_FILE_PATH, callback_detect_event
from wazuh_testing.tools import FileMonitor


# variables

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
test_directories = [os.path.join('/', 'testdir1'),
                    os.path.join('/', 'testdir1', 'subdir'),
                    os.path.join('/', 'testdir1', 'ignore_this'),
                    os.path.join('/', 'testdir2'),
                    os.path.join('/', 'testdir2', 'subdir')
                    ]
testdir1, testdir1_sub, testdir1_ignore, testdir2, testdir2_sub = test_directories

wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)


# configurations

configurations = [
                  # ossec_realtime_1
                  {'section': 'syscheck',
                   'elements': [{'disabled': {'value': 'no'}},
                                {'directories': {'value': '/testdir1',
                                                 'attributes': {'check_all': 'yes',
                                                                'realtime': 'yes'}}}
                                ],
                   'checks': ['realtime']},
                  # ossec_realtime_2
                  {'section': 'syscheck',
                   'elements': [{'disabled': {'value': 'no'}},
                                {'directories': {'value': '/testdir1',
                                                 'attributes': {'check_all': 'yes',
                                                                'realtime': 'yes'}}},
                                {'ignore': {'value': '/testdir1/ignore_this'}}
                                ],
                   'checks': ['realtime']},
                  # ossec_realtime_3
                  {'section': 'syscheck',
                   'elements': [{'disabled': {'value': 'no'}},
                                {'directories': {'value': '/testdir1',
                                                 'attributes': {'check_all': 'yes',
                                                                'realtime': 'yes'}}},
                                {'ignore': {'value': '/testdir1/ignore_this'}},
                                {'ignore': {'value': '/testdir1/not_exists'}}
                                ],
                   'checks': ['realtime']},
                  # ossec_sregex_1
                  {'section': 'syscheck',
                   'elements': [{'disabled': {'value': 'no'}},
                                {'ignore': {'value': '.ignore$',
                                            'attributes': {'type': 'sregex'}}},
                                {'directories': {'value': 'testdir1,/testdir2',
                                                 'attributes': {'check_all': 'yes',
                                                                'realtime': 'yes'}}}
                                ],
                   'checks': ['regex', 'regex1']},
                  # ossec_sregex_2
                  {'section': 'syscheck',
                   'elements': [{'disabled': {'value': 'no'}},
                                {'ignore': {'value': '.ignore$|.ignore2$',
                                            'attributes': {'type': 'sregex'}}},
                                {'directories': {'value': 'testdir1,/testdir2',
                                                 'attributes': {'check_all': 'yes',
                                                                'realtime': 'yes'}}}
                                ],
                   'checks': ['regex', 'regex1']},
                  # ossec_srgex_3
                  {'section': 'syscheck',
                   'elements': [{'disabled': {'value': 'no'}},
                                {'ignore': {'value': '.ignore$',
                                            'attributes': {'type': 'sregex'}}},
                                {'ignore': {'value': '.ignore2$',
                                            'attributes': {'type': 'sregex'}}},
                                {'directories': {'value': 'testdir1,/testdir2',
                                                 'attributes': {'check_all': 'yes',
                                                                'realtime': 'yes'}}},
                                ],
                   'checks': ['regex', 'regex1']},
                  ]


# fixtures

@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# tests

@pytest.mark.parametrize('folder, filename, mode, content, triggers_event, checks', [
    (testdir1, 'testfile', 'w', "Sample content", True, ['realtime']),
    (testdir1, 'btestfile', 'wb', b"Sample content", True, ['realtime']),
    (testdir1, 'testfile2', 'w', "", True, ['realtime']),
    (testdir1, "btestfile2", "wb", b"", True, ['realtime']),
    (testdir1, "btestfile2.ignore", "wb", b"", False, ['regex']),
    (testdir1, "btestfile2.ignored", "wb", b"", True, ['realtime']),
    (testdir1_sub, 'testfile', 'w', "Sample content", True, ['realtime']),
    (testdir1_sub, 'btestfile', 'wb', b"Sample content", True, ['realtime']),
    (testdir1_sub, 'testfile2', 'w', "", True, ['realtime']),
    (testdir1_sub, "btestfile2", "wb", b"", True, ['realtime']),
    (testdir1_sub, ".ignore.btestfile", "wb", b"", True, ['realtime']),
    (testdir2, "another.ignore", "wb", b"other content", False, ['regex']),
    (testdir2, "another.ignored", "wb", b"other content", True, ['regex']),
    (testdir2_sub, "another.ignore", "wb", b"other content", False, ['regex']),
    (testdir2_sub, "another.ignored", "wb", b"other content", True, ['regex']),
    (testdir2, "another.ignored2", "w", "", True, ['regex1']),
    (testdir2, "another.ignored2", "w", "", False, ['regex2', 'regex3'])
])
def test_ignore_subdirectory(folder, filename, mode, content, triggers_event,
                             checks, get_configuration, configure_environment):
    """Checks files are ignored in subdirectory according to configuration

       This test is intended to be used with valid ignore configurations

       :param folder string Directory where the file is being created
       :param filename string Name of the file to be created
       :param mode string same as mode in open built-in function
       :param content string, bytes Content to fill the new file
       :param triggers_event bool True if an event must be generated, False otherwise
       :param checks List to match if the configuration is applied. If the
              configuration does not match the test is skipped
    """
    if not set(checks).intersection(set(get_configuration['checks'])):
        pytest.skip("Does not apply to this config file")

    # Create text files
    with open(os.path.join(folder, filename), mode) as f:
        f.write(content)

    # Fetch the n_regular expected events
    try:
        event = wazuh_log_monitor.start(timeout=3, callback=callback_detect_event).result()
        assert(event['data']['type'] == 'added')
        assert(event['data']['path'] == os.path.join(folder, filename))
    except TimeoutError:
        if triggers_event:
            raise
