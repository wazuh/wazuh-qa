import os

import pytest
from wazuh_testing import global_parameters
import wazuh_testing.fim as fim
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.utils import get_version


# Helper functions
def extra_configuration_after_yield():
    fim.delete_registry(fim.registry_parser[key], sub_key_2, fim.KEY_WOW64_64KEY)


def check_event_type_and_path(fim_event, monitored_registry):
    check_event = False
    if fim_event['type'] == 'added':
        registry_event_path = fim_event['path']
        if monitored_registry.lower() == registry_event_path.lower():
            check_event = True

    return check_event


# Marks
pytestmark = [pytest.mark.win32, pytest.mark.tier(level=0)]

# Variables
key = 'HKEY_LOCAL_MACHINE'
classes_subkey = os.path.join('SOFTWARE', 'Classes')

sub_key_1 = os.path.join(classes_subkey, 'testkey')
sub_key_2 = os.path.join(classes_subkey, 'Testkey')

registry_1, registry_2 = os.path.join(key, sub_key_1), os.path.join(key, sub_key_2)
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')

monitoring_modes = ['scheduled']

# Configurations

conf_params = {'WINDOWS_DUPLICATED_REGISTRY_1': registry_1,
               'WINDOWS_DUPLICATED_REGISTRY_2': registry_2}
configurations_path = os.path.join(test_data_path, 'wazuh_conf_duplicated_registry.yaml')
parameters, metadata = fim.generate_params(extra_params=conf_params, modes=monitoring_modes)
configurations = load_wazuh_configurations(configurations_path, __name__, params=parameters, metadata=metadata)

registry_list = [(key, sub_key_1, fim.KEY_WOW64_64KEY), (key, sub_key_2, fim.KEY_WOW64_64KEY)]
daemons_handler_configuration = {'daemons': ['wazuh-syscheckd']}
local_internal_options = {'syscheck.debug': '2', 'monitord.rotate_log': '0'}


# Fixtures

@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# Test
@pytest.mark.skipif(get_version() != 'v4.2.3', reason="This test fails by wazuh/wazuh#6797, It was fixed on v4.2.3")
@pytest.mark.parametrize('key, subkey1, subkey2, arch', [(key, sub_key_1, sub_key_2, fim.KEY_WOW64_32KEY)])
def test_registry_duplicated_entry(key, subkey1, subkey2, arch, get_configuration, configure_environment,
                                   file_monitoring, configure_local_internal_options_module, daemons_handler_module,
                                   wait_for_fim_start):
    """Two registries with capital differences must trigger just one modify the event.

    Test to check that two registries monitored with the same name but
    capital differences only trigger one added event when the registry is created.


    Params:
        key (str): Name of the root subpath for registries.
        subkey1 (str): Name of the subpath identifying the registry 1 (no capital letter in the name).
        subkey2 (str): Name of the subpath identifying the registry 2 (capital letter in the name).
        arch (str): Value holding the system architecture for registries.
        get_configuration (fixture): Gets the current configuration of the test.
        configure_environment (fixture): Configure the environment for the execution of the test.
        restart_syscheckd (fixture): Restarts syscheck.
        wait_for_fim_start (fixture): Waits until the first FIM scan is completed.

    Raises:
        TimeoutError: If an expected event (registry modified) couldn't be captured.
    """

    mode = get_configuration['metadata']['fim_mode']
    scheduled = mode == 'scheduled'
    monitored_registry = os.path.join(key, subkey2)

    fim.create_registry(fim.registry_parser[key], subkey2, arch)

    fim.check_time_travel(scheduled, monitor=log_monitor)

    fim_event = log_monitor.start(timeout=global_parameters.default_timeout, callback=fim.callback_detect_event,
                                  error_message='Did not receive expected "Sending Fim event: ..." \
                                  event').result()

    if check_event_type_and_path(fim_event['data'], monitored_registry):
        with pytest.raises(TimeoutError):
            fim_event = log_monitor.start(timeout=global_parameters.default_timeout,
                                          callback=fim.callback_detect_event,
                                          error_message='Did not receive expected '
                                          '"Sending Fim event: ..." event').result()

            if check_event_type_and_path(fim_event['data'], monitored_registry):
                raise pytest.fail('Only one added event for the registry was expected.')

    else:
        raise pytest.fail(f"Unexpected fim event detected. Added event for {str(subkey2)} registry was expected.")
