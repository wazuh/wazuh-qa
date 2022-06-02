import pytest
from pytest_ansible_playbook import runner


@pytest.fixture(scope="module")
def run_ansible_playbooks(request):
    # Check if the required attributes are defined.
    import pdb; pdb.set_trace()
    try:
        params = request.module.playbooks
    except AttributeError as e:
        print(e)

    with runner(request, params['setup_playbooks'], params['teardown_playbooks'], params['skip_teardown']):

        yield
