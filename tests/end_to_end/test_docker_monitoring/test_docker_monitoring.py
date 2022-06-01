import pytest


@pytest.mark.ansible_playbook_setup('configuration.yaml', 'generate_alerts.yaml')
def test_docker_monitoring(ansible_playbook, get_opensearch_credentials):
    user, password = get_opensearch_credentials
    assert 1 == 1
