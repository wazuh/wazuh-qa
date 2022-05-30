import pytest


@pytest.mark.ansible_playbook_setup('configuration.yaml', 'generate_alerts.yaml')
def test_docker_monitoring(ansible_playbook):
    assert 1 == 1
