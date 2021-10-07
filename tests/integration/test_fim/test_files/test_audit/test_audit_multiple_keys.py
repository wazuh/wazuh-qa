# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import os

import pytest
import wazuh_testing.fim as fim

from wazuh_testing import global_parameters
from wazuh_testing.tools import PREFIX
from wazuh_testing.tools.configuration import load_wazuh_configurations, check_apply_test, write_wazuh_conf
from wazuh_testing.tools.file import truncate_file
from wazuh_testing.tools.configuration import get_wazuh_conf, set_section_wazuh_conf
from wazuh_testing.tools.services import control_service
import wazuh_testing.tools.monitoring as monitoring
from wazuh_testing.tools import LOG_FILE_PATH

# Marks

pytestmark = [pytest.mark.linux, pytest.mark.tier(level=1)]


local_internal_options = {'syscheck.debug': '2', 'analysisd.debug': '2', 'monitord.rotate_log': '0'}
daemons_handler_configuration = {'daemons': ['wazuh-syscheckd', 'wazuh-analysisd', 'wazuh-modulesd']}



# Variables

monitored_test_dir = os.path.join(PREFIX, 'monitored_test_dir')
non_monitored_test_dir = os.path.join(PREFIX, 'non_monitored_test_dir')
custom_keys = ['key1', 'key2']
param_list = []
audit_rules_reload_interval = 40

param_list = ' '.join([f"-k {key}" for key in custom_keys])

test_directories = [monitored_test_dir, non_monitored_test_dir]
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf_multiple_audit_keys.yaml')

# Configurations

config_params, config_metadata = fim.generate_params(extra_params={'MONITORED_DIR': monitored_test_dir,
                                                     'AUDIT_KEYS': ','.join(key for key in custom_keys)},
                                                     modes=['whodata'])

configurations = load_wazuh_configurations(configurations_path, __name__,
                                           params=config_params, metadata=config_metadata)


# fixtures

@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


@pytest.fixture(scope='module')
def ensure_audit_plugin_installed():
    """ Ensure audit plugin is installed."""

    audit2_plugin = '/etc/audisp/plugins.d/af_wazuh.conf'
    audit3_plugin = '/etc/audit/plugins.d/af_wazuh.conf'

    if not os.path.exists(audit2_plugin) and not os.path.exists(audit3_plugin):

        os.makedirs('/tmp/testing_audit', exist_ok=True)
        configuration_audit = [{'section': 'syscheck', 'elements': [{'disabled': {'value': 'no'}}, 
                               {'directories': {'value': '/tmp/testing_audit', 'attributes': [{'whodata': 'yes'}]}}]}]

        backup_config = get_wazuh_conf()

        # Configuration for testing
        set_section_wazuh_conf(configuration_audit)

        control_service('restart')

        whodata_log_monitor = monitoring.FileMonitor(LOG_FILE_PATH)

        whodata_log_monitor.start(timeout=40, callback=fim.callback_end_audit_reload_rules)

        control_service('stop')

        truncate_file(LOG_FILE_PATH)

        os.system('/sbin/service auditd restart')

        yield

    if not os.path.exists(audit2_plugin) and not os.path.exists(audit3_plugin):
        write_wazuh_conf(backup_config)  


@pytest.fixture(scope='module')
def set_audit_rules(ensure_audit_plugin_installed):
    # Create the custom audit rules for the non monitored directory
    fim.run_audit_command(directory=non_monitored_test_dir, params=param_list, cmd_type='add')
    # Remove audit rule that FIM configures for each monitored directory
    fim.run_audit_command(directory=monitored_test_dir, params='-k wazuh_fim', cmd_type='delete')
    # Set the audit rule for the monitored directory with more than one key
    fim.run_audit_command(directory=monitored_test_dir, params='-k wazuh_fim -k "a_random_key"', cmd_type='add')

    yield

    # Remove the audit rules configured by the test
    fim.run_audit_command(directory=non_monitored_test_dir, params=param_list, cmd_type='delete')
    fim.run_audit_command(directory=monitored_test_dir, params=param_list, cmd_type='delete')


@pytest.mark.parametrize('directory', [monitored_test_dir, non_monitored_test_dir]) 
def test_audit_multiple_keys(up_wazuh_after_module,truncate_log_file_before_module,
                             get_configuration, configure_environment,
                             configure_local_internal_options_module,
                             file_monitoring, set_audit_rules, daemons_handler,
                             wait_for_fim_start, directory):
    """Checks that FIM correctly handles audit rules with multiple keys.

    Args:
        directory (str): Directory where the changes will be done.
        get_configuration (fixture): Gets the current configuration of the test.
        configure_environment (fixture): Configure the environment for the execution of the test.
        restart_syscheckd (fixture): Restarts syscheck.
        wait_for_fim_start (fixture): Waits until the first FIM scan is completed.

    Raises:
        TimeoutError: If an expected event couldn't be captured.
        ValueError: If the path of the event is wrong.
    """
    check_apply_test({'audit_multiple_keys'}, get_configuration['tags'])

    # Wait until FIM reloads the audit rules.
    log_monitor.start(timeout=audit_rules_reload_interval,
                      callback=fim.callback_audit_reloading_rules,
                      error_message='Did not receive expected "Audit reloading rules ..." event ')

    fim.create_file(fim.REGULAR, directory, 'testfile')

    key = log_monitor.start(timeout=global_parameters.default_timeout,
                            callback=fim.callback_get_audit_key,
                            error_message='Did not receive expected "Match audit_key: ..." event ').result()

    assert (key in custom_keys) or (key == 'wazuh_fim'), f"{key} not found in {custom_keys}"

    if directory == '/non_monitored_test_dir':
        with pytest.raises(TimeoutError):
            log_monitor.start(timeout=global_parameters.default_timeout, callback=fim.callback_detect_event,
                              error_message='Did not receive expected "Sending FIM event..." event ')
    else:
        event = log_monitor.start(timeout=global_parameters.default_timeout, callback=fim.callback_detect_event,
                                  error_message='Did not receive expected "Sending FIM event..." event ').result()

        assert get_configuration['metadata']['monitored_dir'] == directory, 'No events should be detected.'
        event_path = event['data']['path']
        assert directory in event_path, f"Expected path = {directory}, event path = {event_path}"
