import pytest
from pytest_ansible_playbook import runner


@pytest.fixture(scope="module")
def run_ansible_playbooks(request):
    """Will run a list of playbooks defined in the 'playbooks' attribute of the executing test function.
    
    The 'playbooks' attribute is a python dictionary with the following structure:
    {
        'setup_playbooks': (list),
        'teardown_playbooks': (list),
        'skip_teardown': (bool)
    }

    Args:
        request (fixture): Provide information on the executing test function.
    """
    # Check if the required attributes are defined.
    try:
        params = request.module.playbooks
    except AttributeError as e:
        print(e)

    with runner(request, params['setup_playbooks'], params['teardown_playbooks'], params['skip_teardown']):

        yield


@pytest.fixture(scope="function")
def run_extra_playbooks(request):
    """Will run a list of playbooks if an element called 'extra_playbooks' exists in the metadata list inside the test
    case YAML file.

    The 'extra_playbooks' is a list of playbook files. Example: ['run_commands.yaml', 'configure_wodle.yaml']

    Args:
        request (fixture): Provide information on the executing test function.
    """
    extra_playbooks = None
    # Get the current test case id
    current_test_case_id = request.node.name.split('[')[1].replace(']', '')

    # Each 'case' has the metadata object of the test case
    for case in request.module.configuration_metadata:
        # Check if the current test case has extra playbooks to run
        if case['name'] == current_test_case_id:
            try:
                extra_playbooks = case['extra_playbooks']
            except KeyError as e:
                pass

    with runner(request, setup_playbooks=extra_playbooks, skip_teardown=True):

        yield
