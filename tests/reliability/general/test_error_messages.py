import pytest
import json
import os
import re

from wazuh_testing import global_parameters

error_codes = ["warnings", "errors", "criticals"]
known_messages_filename = 'know_messages.json'
known_messages_path = os.path.join(os.path.dirname(__file__), known_messages_filename)


target = ["agents", "managers"] if not global_parameters.target_hosts else global_parameters.target_hosts


def get_log_daemon(log_line):
    pattern = re.compile(".*\d+\/\d+\/\d+ \d+:\d+:\d+ (.*?):")
    if pattern.match(log_line):
        print(pattern.match(log_line).group(1))
        return pattern.match(log_line).group(1)
    else:
        return None


@pytest.mark.parametrize('code', error_codes)
@pytest.mark.parametrize('target', target)
def test_error_messages(get_report, code, target):
    unexpected_errors = []
    with open(known_messages_path) as f:
        expected_error_messages = json.loads(f.read())

    for target_messages in get_report[target][code]:
        for error_messages in target_messages.values():
            for error_message in error_messages:
                target_message = True
                if global_parameters.target_daemons:
                    target_message = False
                    for daemon in global_parameters.target_daemons:
                        if get_log_daemon(error_message) == daemon:
                            target_message = True
                            break            
                if target_message:
                    known_error = False
                    if expected_error_messages[code]:
                        combined_known_regex = "(" + ")|(".join(expected_error_messages[code]) + ")"
                        known_error = re.match(combined_known_regex, error_message)

                    if not known_error:
                        unexpected_errors += [error_message]

    assert not unexpected_errors, f"Unexpected error message detected {unexpected_errors}"
