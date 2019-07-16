import pytest

# execute the test: find WARNING message on ossec.log
def test_check_recursion_level_321():
    found = False
    with open('/var/ossec/logs/ossec.log') as ossec_log:
        for line in ossec_log:
            if "ossec-syscheckd: WARNING: Recursion level '321' exceeding limit. Setting 320." in line:
                found = True
    assert found

