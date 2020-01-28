import json, pytest

with open('/var/ossec/logs/alerts/alerts.json') as f:
    alerts_json = [json.loads(line) for line in f]


# execute the test: find test_alert in alerts.json
def test_auto_ignore():
    max_auto_ignore = 5
    output = False
    for alert in alerts_json:
        if alert.get("syscheck",{}).get("path",{}) == "/fim_test/check_auto_ignore_test.txt":
            max_auto_ignore -= 1
    if max_auto_ignore == 0:
        output = True
    assert output

