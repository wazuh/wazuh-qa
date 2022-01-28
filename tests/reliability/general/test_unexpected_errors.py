import pytest
from wazuh_testing import global_parameters

codes = ['criticals', 'errors', 'warnings']
default_targets = ['agents', 'managers']

@pytest.mark.parametrize('code', codes)
@pytest.mark.parametrize('target', default_targets)
def test_remoted_error(get_report, code, target):
    """Check remoted does not have any non expected error
    """
    report = global_parameters.report
    list = report[target]
    for messages in report[target][code]: 
        assert len(messages[code]) == 0, f"{code} detected in {messages['name']} "
