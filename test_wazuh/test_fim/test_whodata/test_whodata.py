# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import os
import glob
import pytest
import time

from wazuh_testing.fim import *
from wazuh_testing.tools import FileMonitor

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')

test_directories = [os.path.join('/', 'testdir1'), os.path.join('/', 'testdir2'), os.path.join('/', 'testdir3'),
                    os.path.join('/', 'testdir4'), os.path.join('/', 'testdir5'), os.path.join('/', 'testdir6'),
                    os.path.join('/', 'testdir7'), os.path.join('/', 'testdir8'), os.path.join('/', 'testdir9'),
                    os.path.join('/', 'testdir0')]
testdir1, testdir2, testdir3, testdir4, testdir5, testdir6, testdir7, testdir8, testdir9, testdir0 = test_directories

wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)


@pytest.fixture(scope='module', params=glob.glob(os.path.join(test_data_path, 'ossec.conf')))
def get_ossec_configuration(request):
    return request.param


@pytest.mark.parametrize('name, filetype, content', [
    ('file1', REGULAR, 'Sample content'),
    #('file2', REGULAR, ''),
    ('file3', REGULAR, b'Sample content')
    #('file4', REGULAR, b'')
])
@pytest.mark.parametrize('folder, checkers', [
    # <directories whodata="yes" check_all="yes" check_sum="no">/testdir1</directories>
    (testdir1, {"hash_md5": "no", "hash_sha1": "no", "hash_sha256": "no"}),
    # <directories whodata="yes" check_all="yes" check_md5sum="no">/testdir2</directories>
    (testdir2, {"hash_md5": "except"}),
    # <directories whodata="yes" check_all="yes" check_sha1sum="no">/testdir3</directories>
    (testdir3, {"hash_sha1": "except"}),
    # <directories whodata="yes" check_all="yes" check_sha256sum="no">/testdir4</directories>
    (testdir4, {"hash_sha256": "except"}),
    # <directories whodata="yes" check_all="yes" check_size="no">/testdir5</directories>
    (testdir5, {"size": "except"}),
    # <directories whodata="yes" check_all="yes" check_owner="no">/testdir6</directories>
    (testdir6, {"uid": "except"}),
    # <directories whodata="yes" check_all="yes" check_group="no">/testdir7</directories>
    (testdir7, {"gid": "except"}),
    # <directories whodata="yes" check_all="yes" check_perm="no">/testdir8</directories>
    (testdir8, {"perm": "except"}),
    # <directories whodata="yes" check_all="yes" check_mtime="no">/testdir9</directories>
    (testdir9, {"mtime": "except"}),
    # <directories whodata="yes" check_all="yes" check_inode="no">/testdir0</directories>
    (testdir0, {"inode": "except"})
])
def test_fim_whodata(folder, name, filetype, content, checkers, configure_environment, restart_wazuh, wait_for_initial_scan):

    # Create file
    create_file(filetype, name, folder, content)

    # Wait until event is detected
    event = wazuh_log_monitor.start(timeout=10, callback=callback_detect_event).result()
    check_checkers(checkers, event)

    # Modify file
    modify_file(folder, name, content)

    # Wait until event is detected
    event = wazuh_log_monitor.start(timeout=10, callback=callback_detect_event).result()
    check_checkers(checkers, event)

    # Delete file
    delete_file(folder, name)

    # Wait until event is detected
    event = wazuh_log_monitor.start(timeout=10, callback=callback_detect_event).result()
    check_checkers(checkers, event)
