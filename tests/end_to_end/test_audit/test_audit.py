import pytest
import os

from wazuh_testing.event_monitor import check_event

alerts_json = os.path.join('/tmp', 'alerts.json')


@pytest.mark.ansible_playbook_setup('credentials.yml', 'configuration.yml', 'generate_events.yml')
def test_audit(ansible_playbook, get_dashboard_credentials, clean_environment):

    expected_alert = r'\{"timestamp":"(\d+\-\d+\-\w+\:\d+\:\d+\.\d+\+\d+)","rule"\:{"level"\:3,"description"\:"Audit\: '\
                        r'Command\: \/usr\/bin\/ping\.","id"\:"80792","firedtimes"\:(\d+).*euid=1000.*' \
                        r'a3=\\"www\.google\.com\\".*\}'

    check_event(callback=expected_alert, file_to_monitor=alerts_json)
