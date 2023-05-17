'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: File Integrity Monitoring (FIM) system watches selected files and triggering alerts when
       these files are modified. Specifically, these tests will verify that FIM generates events
       for file operations in a monitored directory hierarchy using multiple deep levels set in
       the 'recursion_level' attribute.
       The FIM capability is managed by the 'wazuh-syscheckd' daemon, which checks configured
       files for changes to the checksums, permissions, and ownership.

components:
    - fim

suite: files_recursion_level

targets:
    - agent
    - manager

daemons:
    - wazuh-syscheckd

os_platform:
    - linux
    - windows
    - macos
    - solaris

os_version:
    - Arch Linux
    - Amazon Linux 2
    - Amazon Linux 1
    - CentOS 8
    - CentOS 7
    - Debian Buster
    - Red Hat 8
    - Solaris 10
    - Solaris 11
    - macOS Catalina
    - macOS Server
    - Ubuntu Focal
    - Ubuntu Bionic
    - Windows 10
    - Windows Server 2019
    - Windows Server 2016

references:
    - https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html
    - https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/syscheck.html#directories

pytest_args:
    - fim_mode:
        realtime: Enable real-time monitoring on Linux (using the 'inotify' system calls) and Windows systems.
        whodata: Implies real-time monitoring but adding the 'who-data' information.
    - tier:
        0: Only level 0 tests are performed, they check basic functionalities and are quick to perform.
        1: Only level 1 tests are performed, they check functionalities of medium complexity.
        2: Only level 2 tests are performed, they check advanced functionalities and are slow to perform.

tags:
    - fim_recursion_level
'''
import os
import sys

import pytest
from wazuh_testing import global_parameters, LOG_FILE_PATH
from wazuh_testing.fim import callback_audit_event_too_long
from wazuh_testing.tools import PREFIX
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.monitoring import FileMonitor
from wazuh_testing.modules.fim.utils import regular_file_cud, generate_params

# Marks

pytestmark = pytest.mark.tier(level=2)

# Variables

dir_no_recursion = os.path.join(PREFIX, 'test_no_recursion')
dir_recursion_1 = os.path.join(PREFIX, 'test_recursion_1')
dir_recursion_5 = os.path.join(PREFIX, 'test_recursion_5')
dir_recursion_max = os.path.join(PREFIX, 'test_recursion_32') if sys.platform == "win32" else os.path.join(PREFIX, 'test_recursion_320')
subdir = "dir"

dir_no_recursion_space = os.path.join(PREFIX, 'test no recursion')
dir_recursion_1_space = os.path.join(PREFIX, 'test recursion 1')
dir_recursion_5_space = os.path.join(PREFIX, 'test recursion 5')
dir_recursion_max_space = os.path.join(PREFIX, 'test recursion 32') if sys.platform == "win32" else os.path.join(PREFIX, 'test recursion 320')
subdir_space = "dir "

max_recursion = 32 if sys.platform == "win32" else 320

test_directories = [dir_no_recursion, dir_recursion_1, dir_recursion_5, dir_recursion_max, dir_no_recursion_space,
                    dir_recursion_1_space, dir_recursion_5_space, dir_recursion_max_space]

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
conf_name = "wazuh_recursion_windows.yaml" if sys.platform == "win32" else "wazuh_recursion.yaml"
configurations_path = os.path.join(test_data_path, conf_name)
wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)

# configurations

common_params, common_metadata = generate_params(extra_params={'CHECK': {'check_all': 'yes'}})

inode_params, inode_metadata = generate_params(extra_params={'CHECK': {'check_inode': 'no'}})

params = common_params if sys.platform == "win32" else common_params + inode_params
metadata = common_metadata if sys.platform == "win32" else common_metadata + inode_metadata
configurations = load_wazuh_configurations(configurations_path, __name__, params=params, metadata=metadata)


# Functions

def recursion_test(dirname, subdirname, recursion_level, timeout=1, edge_limit=2, ignored_levels=1, is_scheduled=False):
    """
    Check that events are generated in the first and last `edge_limit` directory levels in the hierarchy
    dirname/subdirname1/.../subdirname{recursion_level}. It also checks that no events are generated for
    subdirname{recursion_level+ignored_levels}. All directories and subdirectories needed will be created using the info
    provided by parameter.

    Example:
        recursion_level = 10
        edge_limit = 2
        ignored_levels = 2

        dirname = "/testdir"
        subdirname = "subdir"

        With those parameters this function will create files and expect to detect 'added', 'modified' and 'deleted'
        events for the following directories only, as they are the first and last 2 subdirectories within recursion
        level 10:

        /testdir/subdir1
        /testdir/subdir1/subdir2
        /testdir/subdir1/subdir2/subdir3/subdir4/subdir5/subdir6/subdir7/subdir8/subdir9/
        /testdir/subdir1/subdir2/subdir3/subdir4/subdir5/subdir6/subdir7/subdir8/subdir9/subdir10

        As ignored_levels value is 2, this function will also create files on the following directories and ensure that
        no events are raised as they are outside the recursion level specified:

        /testdir/subdir1/subdir2/subdir3/subdir4/subdir5/subdir6/subdir7/subdir8/subdir9/subdir10/subdir11
        /testdir/subdir1/subdir2/subdir3/subdir4/subdir5/subdir6/subdir7/subdir8/subdir9/subdir10/subdir11/subdir12

    This function also takes into account that a very long path will raise a FileNotFound Exception on Windows because
    of its path length limitations. In a similar way, on Linux environments a `Event Too Long` will be raised if the
    path name is too long.

    Parameters
    ----------
    dirname : str
        The path being monitored by syscheck (indicated in the .conf file).
    subdirname : str
        The name of the subdirectories that will be created during the execution for testing purposes.
    recursion_level : int
        Recursion level. Also used as the number of subdirectories to be created and checked for the current test.
    timeout : int
        Max time to wait until an event is raised.
    edge_limit : int
        Number of directories where the test will monitor events.
    ignored_levels : int
        Number of directories exceeding the specified recursion_level to verify events are not raised.
    is_scheduled : bool
        If True the internal date will be modified to trigger scheduled checks by syschecks.
        False if realtime or Whodata.
    """
    path = dirname
    try:
        # Check True (Within the specified recursion level)
        for n in range(recursion_level):
            path = os.path.join(path, subdirname + str(n + 1))
            if ((recursion_level < edge_limit * 2) or
                    (recursion_level >= edge_limit * 2 and n < edge_limit) or
                    (recursion_level >= edge_limit * 2 and n > recursion_level - edge_limit)):
                regular_file_cud(path, wazuh_log_monitor, time_travel=is_scheduled, min_timeout=timeout)

        # Check False (exceeding the specified recursion_level)
        for n in range(recursion_level, recursion_level + ignored_levels):
            path = os.path.join(path, subdirname + str(n + 1))
            regular_file_cud(path, wazuh_log_monitor, time_travel=is_scheduled, min_timeout=timeout,
                             triggers_event=False)

    except TimeoutError:
        timeout_log_monitor = FileMonitor(LOG_FILE_PATH)
        if timeout_log_monitor.start(timeout=5, callback=callback_audit_event_too_long).result():
            pytest.fail("Audit raised 'Event Too Long' message.")
        raise

    except FileNotFoundError as ex:
        MAX_PATH_LENGTH_WINDOWS_ERROR = 206
        if ex.winerror != MAX_PATH_LENGTH_WINDOWS_ERROR:
            raise

    except OSError as ex:
        MAX_PATH_LENGTH_MACOS_ERROR = 63
        MAX_PATH_LENGTH_SOLARIS_ERROR = 78
        if ex.errno not in (MAX_PATH_LENGTH_SOLARIS_ERROR, MAX_PATH_LENGTH_MACOS_ERROR):
            raise


# Fixtures

@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    return request.param


# Tests

@pytest.mark.parametrize('dirname, subdirname, recursion_level', [
    (dir_no_recursion, subdir, 0),
    (dir_no_recursion_space, subdir_space, 0),
    (dir_recursion_1, subdir, 1),
    (dir_recursion_1_space, subdir_space, 1),
    (dir_recursion_5, subdir, 5),
    (dir_recursion_5_space, subdir_space, 5),
    (dir_recursion_max, subdir, max_recursion),
    (dir_recursion_max_space, subdir_space, max_recursion)
])
@pytest.mark.skip(reason="It will be blocked by wazuh/wazuh#9298, when it was solve we can enable again this test")
def test_recursion_level(dirname, subdirname, recursion_level, get_configuration, configure_environment,
                         restart_syscheckd, wait_for_fim_start):
    '''
    description: Check if the 'wazuh-syscheckd' daemon detects events in a monitored directories hierarchy with
                 deep limited by the 'recursion_level' attribute using 'scheduled', 'realtime', and 'whodata'
                 monitoring modes. For this purpose, the test will monitor a testing folder and create a directory
                 hierarchy inside it. Once FIM starts, it will make file operations in each level of that hierarchy.
                 Finally, the test will verify that the FIM events are generated up to the deep level limit, and no
                 FIM events are generated in the ignored levels.

    wazuh_min_version: 4.2.0

    tier: 2

    parameters:
        - dirname:
            type: str
            brief: Path to the monitored directory (set in the 'ossec.conf' file).
        - subdirname:
            type: str
            brief: Name of the subdirectory to be created.
        - recursion_level:
            type: int
            brief: Number of subdirectories to be created and checked for the current test case.
        - get_configuration:
            type: fixture
            brief: Get configurations from the module.
        - configure_environment:
            type: fixture
            brief: Configure a custom environment for testing.
        - restart_syscheckd:
            type: fixture
            brief: Clear the 'ossec.log' file and start a new monitor.
        - wait_for_fim_start:
            type: fixture
            brief: Wait for realtime start, whodata start, or end of initial FIM scan.

    assertions:
        - Verify that FIM events are generated for the file operations in a monitored directory hierarchy up to
          the level set in the 'recursion_level' attribute.
        - Verify that no FIM events are generated in the ignored directories within a monitored directory hierarchy.

    input_description: A test case (test_recursion_level) is contained in external YAML files
                       (wazuh_recursion.yaml or wazuh_recursion_windows.yaml) which includes
                       configuration settings for the 'wazuh-syscheckd' daemon and the directories
                       to be monitored. These are combined with the recursion levels defined in the module.

    expected_output:
        - r'.*Sending FIM event: (.+)$' ('added', 'modified', and 'deleted' events)
        - r'Caching Audit message: event too long' (if the test case fails)

    tags:
        - realtime
        - scheduled
        - who_data
    '''
    recursion_test(dirname, subdirname, recursion_level, timeout=global_parameters.default_timeout,
                   is_scheduled=get_configuration['metadata']['fim_mode'] == 'scheduled')