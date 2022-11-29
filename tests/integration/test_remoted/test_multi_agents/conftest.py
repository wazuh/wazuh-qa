import pytest

@pytest.fixture(scope='function')
def set_wazuh_configuration_vdt(configuration, set_wazuh_configuration, configure_local_internal_options_vdt):
    """Set wazuh configuration

    Args:
        configuration (dict): Configuration template data to write in the ossec.conf.
        set_wazuh_configuration (fixture): Set the wazuh configuration according to the configuration data.
        configure_local_internal_options_vdt (fixture): Set the local_internal_options.conf file.
    """
    yield