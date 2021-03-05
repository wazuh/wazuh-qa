import datetime
import os
import shutil
import subprocess
import sys

from wazuh_testing.fim import create_file, REGULAR, SYMLINK, callback_symlink_scan_ended, change_internal_options
from wazuh_testing.tools import PREFIX

# variables
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf.yaml')
test_directories = [os.path.join(PREFIX, 'testdir_link'), os.path.join(PREFIX, 'testdir1'),
                    os.path.join(PREFIX, 'testdir2'), os.path.join(PREFIX, 'testdir_target'),
                    os.path.join(PREFIX, 'testdir_not_target'), os.path.join(PREFIX, 'testdir1', 'subdir')]
testdir_link, testdir1, testdir2, testdir_target, testdir_not_target, test_subdir = test_directories
symlink_interval = 20


def debug_sym_check(func):
    """Decorator to see how long it's taking wazuh log monitor to detect the sym_check event"""

    def wrapper(*args, **kwargs):
        now1 = datetime.datetime.now()
        func(*args, **kwargs)
        now2 = datetime.datetime.now()
        seconds = (now2 - now1).seconds
        print(f'^^^ Symlink check ^^^ - {seconds} / {symlink_interval} seconds')

    return wrapper


def modify_symlink(target, path, file=None):
    """Modify an existing symbolic link to point to another file or directory"""
    if file is not None:
        target = os.path.join(target, file)
    if sys.platform == "sunos5":
        if os.path.exists(path):
            os.remove(path)
        os.symlink(target, path)
    else:
        subprocess.call(['ln', '-sfn', target, path])


def delete_f(path, file=None):
    """Delete given path. Directory or file"""
    if file is None:
        shutil.rmtree(path, ignore_errors=True)
    else:
        regular_path = os.path.join(path, file)
        if os.path.exists(regular_path):
            os.remove(regular_path)


@debug_sym_check
def wait_for_symlink_check(monitor):
    """Wait for symlink thread to finish its scan"""
    monitor.start(timeout=(symlink_interval + 2), callback=callback_symlink_scan_ended,
                  error_message='Did not receive expected "Links check finalized" event')


def extra_configuration_before_yield():
    """Create files and symlinks"""
    symlinkdir = testdir_link
    create_file(REGULAR, testdir1, 'regular1', content='')
    create_file(REGULAR, testdir1, 'regular2', content='')
    create_file(REGULAR, testdir2, 'regular1', content='')
    create_file(REGULAR, testdir2, 'regular2', content='')
    create_file(REGULAR, test_subdir, 'regular1', content='')
    create_file(REGULAR, test_subdir, 'regular2', content='')
    # Symlink pointing to /testdir1/regular1
    create_file(SYMLINK, symlinkdir, 'symlink', target=os.path.join(testdir1, 'regular1'))
    # Symlink pointing to /testdir_target/
    create_file(SYMLINK, symlinkdir, 'symlink2', target=testdir_target)
    # Symlink pointing to /testdir1
    create_file(SYMLINK, symlinkdir, 'symlink3', target=testdir1)
    # Set symlink_scan_interval to a given value
    change_internal_options(param='syscheck.symlink_scan_interval', value=symlink_interval)


def extra_configuration_after_yield():
    """Set symlink_scan_interval to default value"""
    change_internal_options(param='syscheck.symlink_scan_interval', value=600)
