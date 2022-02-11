import pytest
import json
from wazuh_testing import global_parameters
import re

codes = ['criticals', 'errors', 'warnings']
default_targets = ['agents', 'managers']

@pytest.mark.parametrize('code', codes)
@pytest.mark.parametrize('target', default_targets)
def test_unexpected_errors(get_report, code, target):
    """Check remoted does not have any non expected error
    """
    report = global_parameters.report
    list = report[target]
    unexpected_errors = []

    for hosts in report[target][code]:
        for messages in hosts.values():
            for message in messages:
                with open('tests/reliability/general/know_messages.json') as f:
                    expected = json.loads(f.read())
                    combined = "(" + ")|(".join(expected[code]) + ")"
                    if not re.match(combined, message):
                        unexpected_errors += [message]
    assert not unexpected_errors