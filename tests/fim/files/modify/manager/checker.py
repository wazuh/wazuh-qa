import json, pytest, sys, os

with open('/var/ossec/logs/alerts/alerts.json') as f:
    alerts_json = [json.loads(line) for line in f]

with open(os.path.dirname(sys.argv[0]) + '/' + 'check_alert_new_files_modify.json') as f:
    test_alert = json.load(f)

# delete the keys that we don't want to check in our FIM testing
def prune_json_fim(alert):
    if alert.get('timestamp',{}):
        del alert['timestamp']

    if alert.get('rule',{}).get('firedtimes'):
        del alert['rule']['firedtimes']
    if alert.get('rule',{}).get('mail'):
        del alert['rule']['mail']

    if alert.get('agent',{}):
        del alert['agent']

    if alert.get('manager',{}):
        del alert['manager']

    if alert.get('id',{}):
        del alert['id']

    if alert.get('full_log',{}):
        del alert['full_log']

    if alert.get('syscheck',{}).get('mtime_before'):
        del alert['syscheck']['mtime_before']
    if alert.get('syscheck',{}).get('mtime_after'):
        del alert['syscheck']['mtime_after']
    if alert.get('syscheck',{}).get('inode_before'):
        del alert['syscheck']['inode_before']
    if alert.get('syscheck',{}).get('inode_after'):
        del alert['syscheck']['inode_after']


# execute the test: find test_alert in alerts.json
def test_check_alert_new_files_modify():
    found = False
    prune_json_fim(test_alert)
    for alert in alerts_json:
        prune_json_fim(alert)
        if alert == test_alert:
            found = True
        if alert.get("syscheck",{}).get("event",{}) == "added":
            found = False
            break
    assert found

