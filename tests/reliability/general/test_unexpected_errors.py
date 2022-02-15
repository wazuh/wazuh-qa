import pytest
import json
import os
import re

codes = ['criticals', 'errors', 'warnings']
default_targets = ['agents', 'managers']

known_messages_filename = 'know_messages.json'
known_messages_path = os.path.join(os.path.dirname(__file__), known_messages_filename)


@pytest.mark.parametrize('code', codes)
@pytest.mark.parametrize('target', default_targets)
def test_unexpected_errors(get_report, code, target):
    unexpected_errors = []

    for hosts in get_report[target][code]:
        for messages in hosts.values():
            for message in messages:
                with open(known_messages_path) as f:
                    expected = json.loads(f.read())
                    combined = "(" + ")|(".join(expected[code]) + ")"
                    if not re.match(combined, message):
                        unexpected_errors += [message]
    assert not unexpected_errors
