import pytest


@pytest.mark.ansible_playbook_setup('configuration.yml', 'generate_events.yml', 'get_alerts.yml')
def test_bar(ansible_playbook):
    assert 1 == 1
