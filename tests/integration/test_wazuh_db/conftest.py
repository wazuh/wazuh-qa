import pytest

from wazuh_testing.tools.wazuh_manager import create_group, delete_group


@pytest.fixture(scope='function')
def create_groups(test_case):
    if 'pre_required_group' in test_case:
        groups = test_case['pre_required_group'].split(',')

        for group in groups:
            create_group(group)

    yield

    if 'pre_required_group' in test_case:
        groups = test_case['pre_required_group'].split(',')

        for group in groups:
            delete_group(group)
