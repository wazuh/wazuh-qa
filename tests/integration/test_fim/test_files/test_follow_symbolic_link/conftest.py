import os
import pytest

from wazuh_testing.fim import create_file, REGULAR, SYMLINK, change_internal_options
from test_fim.test_files.test_follow_symbolic_link.common import (testdir1, testdir2, testdir_link, testdir_target,
                                                           test_subdir, symlink_interval)


@pytest.fixture()
def prepare_symlinks():
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
    
    yield

    # Set symlink_scan_interval to default value
    change_internal_options(param='syscheck.symlink_scan_interval', value=600)
