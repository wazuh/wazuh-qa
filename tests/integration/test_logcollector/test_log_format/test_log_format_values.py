'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: The 'wazuh-logcollector' daemon monitors configured files and commands for new log messages.
       Specifically, these tests will check if the logcollector accepts only allowed values for
       the 'log_format' tag, and the log file to monitor has compatible content with those values.
       Log data collection is the real-time process of making sense out of the records generated
       by servers or devices. This component can receive logs through text files or Windows
       event logs. It can also directly receive logs via remote syslog which is useful
       for firewalls and other such devices.

components:
    - logcollector

suite: log_format

targets:
    - agent
    - manager

daemons:
    - wazuh-logcollector

os_platform:
    - linux
    - windows

os_version:
    - Arch Linux
    - Amazon Linux 2
    - Amazon Linux 1
    - CentOS 8
    - CentOS 7
    - Debian Buster
    - Red Hat 8
    - Ubuntu Focal
    - Ubuntu Bionic
    - Windows 10
    - Windows Server 2019
    - Windows Server 2016

references:
    - https://documentation.wazuh.com/current/user-manual/capabilities/log-data-collection/index.html
    - https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/localfile.html#log-format

tags:
    - logcollector_log_format
'''
import os
import pytest
import sys
import wazuh_testing.tools.file as file

import wazuh_testing.logcollector as logcollector
from wazuh_testing.tools import LOG_FILE_PATH
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.monitoring import FileMonitor
from wazuh_testing.tools.services import control_service

# Marks
pytestmark = pytest.mark.tier(level=0)

# Configuration
no_restart_windows_after_configuration_set = True
force_restart_after_restoring = True
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf.yaml')
local_internal_options = {'windows.debug': '2', 'agent.debug': '0', 'logcollector.debug':'2'}

if sys.platform == 'win32':
    location = r'C:\test.txt'
    iis_path = r'C:\test_iis.log'
else:
    location = '/tmp/test.txt'
    file_multilog = '/var/log/current'
    nmap_log = '/var/log/nmap.log'

parameters = [
    {'LOCATION': f'{location}', 'LOG_FORMAT': 'json'},
    {'LOCATION': f'{location}', 'LOG_FORMAT': 'json'},
    {'LOCATION': f'{location}', 'LOG_FORMAT': 'syslog'},
    {'LOCATION': f'{location}', 'LOG_FORMAT': 'snort-full'},
    {'LOCATION': f'{location}', 'LOG_FORMAT': 'squid'},
    {'LOCATION': f'{location}', 'LOG_FORMAT': 'audit'},
    {'LOCATION': f'{location}', 'LOG_FORMAT': 'audit'},
    {'LOCATION': f'{location}', 'LOG_FORMAT': 'mysql_log'},
    {'LOCATION': f'{location}', 'LOG_FORMAT': 'postgresql_log'}
]

metadata = [
    {'location': f'{location}', 'log_format': 'json', 'valid_value': True},
    {'location': f'{location}', 'log_format': 'json', 'valid_value': False},
    {'location': f'{location}', 'log_format': 'syslog', 'valid_value': True},
    {'location': f'{location}', 'log_format': 'snort-full', 'valid_value': True},
    {'location': f'{location}', 'log_format': 'squid', 'valid_value': True},
    {'location': f'{location}', 'log_format': 'audit', 'valid_value': False},
    {'location': f'{location}', 'log_format': 'audit', 'valid_value': True},
    {'location': f'{location}', 'log_format': 'mysql_log', 'valid_value': True},
    {'location': f'{location}', 'log_format': 'postgresql_log', 'valid_value': True}
]

if sys.platform == 'win32':
    parameters.append({'LOCATION': 'Security', 'LOG_FORMAT': 'eventlog'})
    parameters.append({'LOCATION': 'Application', 'LOG_FORMAT': 'eventchannel'})
    parameters.append({'LOCATION': f'{iis_path}', 'LOG_FORMAT': 'iis'})

    metadata.append({'location': 'Security', 'log_format': 'eventlog', 'valid_value': True})
    metadata.append({'location': 'Application', 'log_format': 'eventchannel', 'valid_value': True})
    metadata.append({'location': f'{iis_path}', 'log_format': 'iis', 'valid_value': True})
else:

    parameters.append({'LOCATION': f'{location}', 'LOG_FORMAT': 'multi-line:3'})
    parameters.append({'LOCATION': f'{file_multilog}', 'LOG_FORMAT': 'djb-multilog'})
    parameters.append({'LOCATION': f'{file_multilog}', 'LOG_FORMAT': 'djb-multilog'})
    parameters.append({'LOCATION': f'{nmap_log}', 'LOG_FORMAT': 'nmapg'})
    parameters.append({'LOCATION': f'{nmap_log}', 'LOG_FORMAT': 'nmapg'})

    metadata.append({'location': f'{location}', 'log_format': 'multi-line:3', 'valid_value': True})
    metadata.append({'location': f'{file_multilog}', 'log_format': 'djb-multilog', 'valid_value': True})
    metadata.append({'location': f'{file_multilog}', 'log_format': 'djb-multilog', 'valid_value': False})
    metadata.append({'location': f'{nmap_log}', 'log_format': 'nmapg', 'valid_value': False})
    metadata.append({'location': f'{nmap_log}', 'log_format': 'nmapg', 'valid_value': True})

configurations = load_wazuh_configurations(configurations_path, __name__, params=parameters, metadata=metadata)
configuration_ids = [f"{x['log_format'], x['valid_value']}" for x in metadata]

log_format_windows_print_analyzing_info = ['eventlog', 'eventchannel', 'iis']
log_format_not_print_reading_info = ['audit', 'mysql_log', 'postgresql_log', 'nmapg', 'djb-multilog', 'iis']


# fixtures
@pytest.fixture(scope="module", params=configurations, ids=configuration_ids)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


def create_file_location(filename, type):
    """Creates a file with specific content for a log format particular.

     Args:
          filename (str): filename to create
          type (str): type of record format with which the filename will be created.
    """
    if type == 'iis':
        data = '#Software: Microsoft Internet Information Server 6.0\n#Version: 1.0\n#Date: 1998-11-19 22:48:39'
        data += '#Fields: date time c-ip cs-username s-ip cs-method cs-uri-stem cs-uri-query sc-status sc-bytes '
        data += 'cs-bytes time-taken cs-version cs(User-Agent) cs(Cookie) cs(Referrer)\n'
    else:
        data = ""
    file.write_file(filename, data)


def modify_json_file(filename, valid):
    """Adds content in JSON format with valid or invalid values.

    Args:
        filename (str): file's path to modify.
        valid (bool): type of content value. It can be valid or invalid.
    """
    data = '{"issue":22,"severity":1}\n' if valid else '{"issue:22,"severity":1}\n'
    file.write_file(filename, data)


def modify_syslog_file(filename):
    """Adds content with valid values in Syslog format.

    Args:
        filename (str): file's path to modify.
    """
    data = 'Apr 29 12:47:51 dev-branch systemd[1]: Starting\n'
    file.write_file(filename, data)


def modify_snort_file(filename):
    """Adds content with valid values in snort-full format.

    Args:
        filename (str): file's path to modify.
    """
    data = '10/12-21:29:35.911089 {ICMP} 192.168.1.99 – > 192.168.1.103\n'
    file.write_file(filename, data)


def modify_squid_file(filename):
    """Adds content with valid values in squid format.

    Args:
        filename (str): file's path to modify.
    """
    data = '902618.84 440 120.65.1.1 TCP/304 80 GET http://www.web.com:8005\n'
    file.write_file(filename, data)


def modify_audit_file(filename, valid):
    """Adds content in audit format with valid or invalid values.

    Args:
        filename (str): file's path to modify.
        valid (bool): type of content value. It can be valid or invalid.
    """
    if valid:
        data = """type=SERVICE_START msg=audit(1620164215.922:963): pid=1 uid=0 auid=4294967295 ses=4294967295 """
        data += """subj=system_u:system_r:init_t:s0 msg='unit=dnf-makecache comm="systemd" """
        data += """exe="/usr/lib/systemd/systemd" """
        data += """hostname=? addr=? terminal=? res=success'UID="root" AUID="unset"\n"""

    else:
        data = """=SERVICE_START msg=audit(1620164215.922:963): pid=1 uid=0 auid=4294967295 """
        data += """ses=4294967295 subj=system_u:system_r:init_t:s0 msg='unit=dnf-makecache comm="systemd" """
        data += """exe="/usr/lib/systemd/systemd" hostname=? addr=? terminal=? res=success'UID="root" AUID="unset\n"""
    file.write_file(filename, data)


def modify_mysqlog_file(filename):
    """Adds content with valid values in MySQL format.

    Args:
        filename (str): file's path to modify.
    """
    data = """show variables like 'general_log%';\n"""
    file.write_file(filename, data)


def modify_postgresqlog_file(filename):
    """Adds content with valid values in Postgresql format.

    Args:
        filename (str): file's path to modify.
    """
    data = "show variables like 'general_log%';\n"
    file.write_file(filename, data)


def modify_nmapg_file(filename, valid):
    """Adds content in nmapg format with valid or invalid values.

    Args:
        filename (str): file's path to modify.
        valid (bool): type of content value. It can be valid or invalid.
    """
    if valid:
        data = '# Nmap 7.70 scan initiated Tue May 11 16:48:35 2021 as: nmap -T4 -A -v '
        data += '-oG /var/log/map.log scanme.nmap.org\n'
        data += '# Ports scanned: TCP(1000;1,3-4,6-7,9,13,17,7920-7921,7937-7938,7999-8002,8007-8011,8021-8022,8031,'
        data += '8042,8045,8800,64680,65000,65129,65389) UDP(0;) SCTP(0;) PROTOCOLS(0;)\n'
    else:
        data = 'nmap -n -Pn -p 80 --open -sV -vvv --script banner,http-title -iR 1000\n'
    file.write_file(filename, data)


def modify_djb_multilog_file(filename, valid):
    """Adds content in djb-multilog format with valid or invalid values.

    Args:
        filename (str): file's path to modify.
        valid (bool): type of content value. It can be valid or invalid.
    """
    if valid:
        data = '@400000003b4a39c23294b13c fatal: out of memory'
    else:
        data = '@40000000590e30983973bda4-eError'

    file.write_file(filename, data)


def modify_multi_line_file(filename):
    """Adds content with valid values in multi-line format.

    Args:
        filename (str): file's path to modify.
    """
    data = "Aug 9 14:22:47 log1\nAug 9 14:22:47 log2\nAug 9 14:22:47 log3\n"
    file.write_file(filename, data)


def modify_iis_file(filename):
    """Adds content in iis format with valid values.

    Args:
        filename (str): file's path to modify.
    """
    data = '2020-11-19 22:48:39 206.175.82.5 - 208.201.133.173 GET /global/images/navlineboards.gif '
    data += '- 200 540 324 157 HTTP/1.0 Mozilla/4.0+(compatible;+MSIE+4.01;+Windows+95) '
    data += 'USERID=CustomerA;+IMPID=01234 http://www.loganalyzer.net\n'
    file.write_file(filename, data)


def modify_file(file, type, content):
    """Modifies a file's content to generate logs.

    Args:
        file (str): file's path to modify.
        type (str): log format type.
        content (bool): content type(Valid=True, Invalid=False) to add in the file.
    """
    if type == 'json':
        modify_json_file(file, content)
    elif type == 'syslog':
        modify_syslog_file(file)
    elif type == 'snort-full':
        modify_snort_file(file)
    elif type == 'squid':
        modify_squid_file(file)
    elif type == 'audit':
        modify_audit_file(file, content)
    elif type == 'mysql_log':
        modify_mysqlog_file(file)
    elif type == 'postgresql_log':
        modify_postgresqlog_file(file)
    elif type == 'nmapg':
        modify_nmapg_file(file, content)
    elif type == 'djb-multilog':
        modify_djb_multilog_file(file, content)
    elif type == 'multi-line:3':
        modify_multi_line_file(file)
    elif type == 'iis':
        modify_iis_file(file)


def check_log_format_valid(cfg):
    """Checks if Wazuh runs correctly with the specified log formats.

    Args:
        cfg (dict): Dictionary with the localfile configuration.
    Raises:
        TimeoutError: If the "Analyzing file" callback is not generated.
    """
    wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)

    if cfg['log_format'] == 'eventchannel' or cfg['log_format'] == 'eventlog':
        log_callback = logcollector.callback_eventchannel_analyzing(cfg['location'])
    else:
        log_callback = logcollector.callback_analyzing_file(cfg['location'])

    wazuh_log_monitor.start(timeout=5, callback=log_callback,
                            error_message=logcollector.GENERIC_CALLBACK_ERROR_ANALYZING_FILE)


def check_log_format_value_valid(conf):
    """Checks if Wazuh runs correctly with the correct log format and specific content.

    Args:
        conf (dict): Dictionary with the localfile configuration.
    Raises:
        TimeoutError: If the "Analyzing file" callback is not generated.
    """
    wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)

    if conf['log_format'] not in log_format_windows_print_analyzing_info:
        if conf['log_format'] in log_format_not_print_reading_info:
            # Logs format that only shows when a specific file is read.

            log_callback = logcollector.callback_read_file(conf['location'])
            wazuh_log_monitor.start(timeout=5, callback=log_callback,
                                    error_message=logcollector.GENERIC_CALLBACK_ERROR_READING_FILE)

        elif conf['log_format'] == 'multi-line:3':
            # It is necessary to reorganize the content of the file to compare it
            # with the generated output of the 'multiline' format.

            msg = ""
            with open(location, 'r') as file:
                for line in file:
                    msg += line.rstrip('\n')
                    msg += ' '
                log_callback = logcollector.callback_reading_file(conf['log_format'], msg.rstrip(' '))
                wazuh_log_monitor.start(timeout=5, callback=log_callback,
                                        error_message=logcollector.GENERIC_CALLBACK_ERROR_READING_FILE)
        else:
            # Verify that the content of the parsed file is equal to the output generated in the logs.
            with open(location, 'r') as f:
                lines = f.readlines()
                for line in lines:
                    log_callback = logcollector.callback_reading_file(conf['log_format'], line.rstrip('\n'))
                    wazuh_log_monitor.start(timeout=5, callback=log_callback,
                                            error_message=logcollector.GENERIC_CALLBACK_ERROR_READING_FILE)


def analyzing_invalid_value(conf):
    """Checks for the error message that is shown when the record format type is valid but the content is invalid.

    Args:
        conf (dict): Dictionary with the localfile configuration.
    Returns:
        callable: callback to detect this event log.
    """
    with open(conf['location']) as log:
        line = log.readline()
        log_callback = logcollector.callback_invalid_format_value(line.rstrip('\n'),
                                                                  conf['log_format'], conf['location'])
    return log_callback


def check_log_format_value_invalid(conf):
    """Check if Wazuh fails because of content invalid log.

    Args:
        conf (dict): Dictionary with the localfile configuration.
    Raises:
       TimeoutError: If error callback are not generated.
   """
    wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)

    if conf['log_format'] not in log_format_windows_print_analyzing_info:
        log_callback = analyzing_invalid_value(conf)
        wazuh_log_monitor.start(timeout=5, callback=log_callback, error_message=logcollector.GENERIC_CALLBACK_ERROR)


def check_log_format_values(conf):
    """Set of validations to follow to validate a certain content.
    The file content could be valid or invalid.

    Args:
        conf (dict): Dictionary with the localfile configuration.
   """
    check_log_format_valid(conf)
    modify_file(conf['location'], conf['log_format'], conf['valid_value'])

    if conf['valid_value']:
        check_log_format_value_valid(conf)
    else:
        check_log_format_value_invalid(conf)
    file.remove_file(conf['location'])


def test_log_format(configure_local_internal_options_module, get_configuration, configure_environment):
    '''
    description: Check if the 'wazuh-logcollector' accepts only allowed values for the 'log_format' tag, and the content
                 of the log file to monitor is compatible with those values. For this purpose, the test will create a
                 testing log file, configure a 'localfile' section to monitor it, and set the 'log_format' tag with
                 valid/invalid values. Then, it will check if an error event is triggered when the value used is
                 invalid. Finally, the test will verify that an 'analyzing' event is generated if the content of
                 the monitored log file is compatible with the log format, or an error event is generated if not.

    wazuh_min_version: 4.2.0

    tier: 0

    parameters:
        - configure_local_internal_options_module:
            type: fixture
            brief: Set internal configuration for testing.
        - get_configuration:
            type: fixture
            brief: Get configurations from the module.
        - configure_environment:
            type: fixture
            brief: Configure a custom environment for testing.

    assertions:
        - Verify that the logcollector accepts only valid values for the 'log_format' tag.
        - Verify that the logcollector generates error events when using valid values for the 'log_format' tag
          but the log file has invalid content.
        - Verify that the logcollector monitors log files when using valid values for the 'log_format' tag and
          the log file has valid content.

    input_description: A configuration template (test_log_format_values) is contained in an external YAML
                       file (wazuh_conf.yaml). That template is combined with different test cases defined
                       in the module. Those include configuration settings for the 'wazuh-logcollector' daemon.

    expected_output:
        - r'Analyzing event log.*'
        - r'Analyzing file.*'
        - r'lines from .*'
        - r'Reading json message.*'
        - r'Reading syslog message.*'
        - r'Reading message.*'
        - r'Line .* read from .* is not a JSON object.'
        - r'Discarding audit message because of invalid syntax.'
        - r'Bad formated nmap grepable file.'
        - r'Invalid DJB log.*'

    tags:
        - logs
    '''
    conf = get_configuration['metadata']

    control_service('stop')
    file.truncate_file(LOG_FILE_PATH)

    if conf['valid_value']:
        # Analyze valid formats with valid content in Windows
        if sys.platform == 'win32':
            if conf['log_format'] == 'iis':
                create_file_location(iis_path, conf['log_format'])
            control_service('start')
            check_log_format_valid(conf)
        else:
            # Analyze valid formats with valid content in Linux
            create_file_location(conf['location'], conf['log_format'])
            control_service('start')
            check_log_format_values(conf)

    else:
        # Analyze valid formats with invalid content in Linux
        create_file_location(conf['location'], conf['log_format'])
        control_service('start')
        check_log_format_values(conf)
