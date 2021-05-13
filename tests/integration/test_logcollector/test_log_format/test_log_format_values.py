# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import pytest
import sys
import subprocess as sb
import wazuh_testing.tools.file as file

import wazuh_testing.logcollector as logcollector
from wazuh_testing.tools import LOG_FILE_PATH
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.monitoring import LOG_COLLECTOR_DETECTOR_PREFIX, AGENT_DETECTOR_PREFIX, FileMonitor
from wazuh_testing.tools.services import control_service

LOGCOLLECTOR_DAEMON = "wazuh-logcollector"

# Marks
pytestmark = pytest.mark.tier(level=0)

# Configuration
no_restart_windows_after_configuration_set = True
force_restart_after_restoring = True
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf.yaml')

local_internal_options = {'logcollector.vcheck_files': '1', 'logcollector.debug': '2', 'monitord.rotate_log': '0'}

if sys.platform == 'win32':
    location = r'C:\test.txt'
#    iis_path = r'%SystemDrive%\inetpub\logs\LogFiles\W3SVC1\test.log'
    iis_path = r'C:\test_iis.log'
    filemultilog = r'C:\test_multilog'
    nmap_log = r'C:\test_nmapg.log'
    wazuh_configuration = 'ossec.conf'
    prefix = AGENT_DETECTOR_PREFIX

else:
    location = '/tmp/test.txt'
    filemultilog = '/var/log/current'
    nmap_log = '/var/log/wa.log'
    wazuh_configuration = 'etc/ossec.conf'
    prefix = LOG_COLLECTOR_DETECTOR_PREFIX

parameters = [
    {'LOCATION': f'{location}', 'LOG_FORMAT': 'json'},
    {'LOCATION': f'{location}', 'LOG_FORMAT': 'json'},
    {'LOCATION': f'{location}', 'LOG_FORMAT': 'syslog'},
    {'LOCATION': f'{location}', 'LOG_FORMAT': 'snort-full'},
    {'LOCATION': f'{location}', 'LOG_FORMAT': 'squid'},
    {'LOCATION': f'{location}', 'LOG_FORMAT': 'audit'},
    {'LOCATION': f'{location}', 'LOG_FORMAT': 'audit'},
    {'LOCATION': f'{location}', 'LOG_FORMAT': 'mysql_log'},
    {'LOCATION': f'{location}', 'LOG_FORMAT': 'postgresql_log'},
    {'LOCATION': f'{location}', 'LOG_FORMAT': 'multi-line:3'},
    {'LOCATION': f'{filemultilog}', 'LOG_FORMAT': 'djb-multilog'},
    {'LOCATION': f'{filemultilog}', 'LOG_FORMAT': 'djb-multilog'},
    {'LOCATION': f'{location}', 'LOG_FORMAT': 'nmapg'},
    {'LOCATION': f'{nmap_log}', 'LOG_FORMAT': 'nmapg'},
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
    {'location': f'{location}', 'log_format': 'postgresql_log', 'valid_value': True},
    {'location': f'{location}', 'log_format': 'multi-line:3', 'valid_value': True},
    {'location': f'{filemultilog}', 'log_format': 'djb-multilog', 'valid_value': False},
    {'location': f'{filemultilog}', 'log_format': 'djb-multilog', 'valid_value': True},
    {'location': f'{location}', 'log_format': 'nmapg', 'valid_value': False},
    {'location': f'{nmap_log}', 'log_format': 'nmapg', 'valid_value': True},
]

if sys.platform == 'win32':
    parameters.append({'LOCATION': 'Security', 'LOG_FORMAT': 'eventlog'})
    parameters.append({'LOCATION': 'Application', 'LOG_FORMAT': 'eventchannel'})
    parameters.append({'LOCATION': f'{iis_path}', 'LOG_FORMAT': 'iis'})

    metadata.append({'location': 'Security', 'log_format': 'eventlog', 'valid_value': True})
    metadata.append({'location': 'Application', 'log_format': 'eventchannel', 'valid_value': True})
    metadata.append({'location': f'{iis_path}', 'log_format': 'iis', 'valid_value': True}),

configurations = load_wazuh_configurations(configurations_path, __name__, params=parameters, metadata=metadata)
configuration_ids = [f"{x['log_format'], x['valid_value']}" for x in metadata]

log_format_windows_print_analyzing_info = ['eventlog', 'eventchannel', 'iis']
log_format_not_print_reading_info = ['audit', 'mysql_log', 'postgresql_log', 'nmapg', 'djb-multilog']

# fixtures
@pytest.fixture(scope="module", params=configurations, ids=configuration_ids)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param

@pytest.fixture(scope="module")
def get_local_internal_options():
    """Get configurations from the module."""
    return local_internal_options

def create_file(file, type):
    """Create an empty file."""
    if type == 'iis':
        data = '#Software: Microsoft Internet Information Server 6.0\n#Version: 1.0\n#Date: 1998-11-19 22:48:39'
        data += '#Fields: date time c-ip cs-username s-ip cs-method cs-uri-stem cs-uri-query sc-status sc-bytes cs-bytes time-taken cs-version cs(User-Agent) cs(Cookie) cs(Referrer)\n'
    else:
        data = ""
    with open(file, 'a') as f:
        f.write(data)

def modify_json_file(file, type):
    """Create a json content with an specific values"""
    if type:
        data = '{"issue":22,"severity":1}\n'
    else:
        data = '{"issue:22,"severity":1}\n'

    with open(file, 'a') as f:
        f.write(data)

def modify_syslog_file(file):
    """Create a syslog content with an specific values"""
    data = 'Apr 29 12:47:51 dev-branch systemd[1]: Starting\n'

    with open(file, 'a') as f:
        f.write(data)

def modify_snort_file(file):
    """Create a snort content with an specific values"""
    data = '10/12-21:29:35.911089 {ICMP} 192.168.1.99 – > 192.168.1.103\n'

    with open(file, 'a') as f:
        f.write(data)

def modify_squid_file(file):
    """Create a squid content with an specific values"""
    data = '902618.84 440 120.65.1.1 TCP/304 80 GET http://www.web.com:8005\n'
    with open(file, 'a') as f:
        f.write(data)

def modify_audit_file(file, type):
    """Create a audit content with an specific values"""
    if type:
        data = """type=SERVICE_START msg=audit(1620164215.922:963): pid=1 uid=0 auid=4294967295 ses=4294967295 subj=system_u:system_r:init_t:s0 msg='unit=dnf-makecache comm="systemd" exe="/usr/lib/systemd/systemd" hostname=? addr=? terminal=? res=success'UID="root" AUID="unset"\n"""
    else:
        data = """=SERVICE_START msg=audit(1620164215.922:963): pid=1 uid=0 auid=4294967295 ses=4294967295 subj=system_u:system_r:init_t:s0 msg='unit=dnf-makecache comm="systemd" exe="/usr/lib/systemd/systemd" hostname=? addr=? terminal=? res=success'UID="root" AUID="unset\n"""
    with open(file, 'a') as f:
        f.write(data)

def modify_mysqlLog_file(file):
    """Create a mysql_log content with an specific values"""
    data = """show variables like 'general_log%';\n"""
    with open(file, 'a') as f:
        f.write(data)

def modify_postgresqlLog_file(file):
    """Create a postgresql_log content with an specific values"""
    data = """show variables like 'general_log%';\n"""
    with open(file, 'a') as f:
        f.write(data)

def modify_nmapg_file(file, type):
    """Create a nmapg content with an specific values"""
    if type:
        data = '# Nmap 7.70 scan initiated Tue May 11 16:48:35 2021 as: nmap -T4 -A -v -oG /var/log/map.log scanme.nmap.org\n'
        data += '# Ports scanned: TCP(1000;1,3-4,6-7,9,13,17,7920-7921,7937-7938,7999-8002,8007-8011,8021-8022,8031,8042,8045,8800,64680,65000,65129,65389) UDP(0;) SCTP(0;) PROTOCOLS(0;)\n'
    else:
        data = 'nmap -n -Pn -p 80 --open -sV -vvv --script banner,http-title -iR 1000\n'
    with open(file, 'a') as f:
        f.write(data)

def modify_djb_multilog_file(file, type):
    """Create a djb-multilog content with an specific values"""
    if type:
        data = '@400000003b4a39c23294b13c fatal: out of memory'
    else:
        data = '@40000000590e30983973bda4-eError'

    with open(file, 'a') as f:
        f.write(data)

def modify_multi_line_file(file):
    """Create a multi-line content with an specific values"""

    data = """Aug 9 14:22:47 log1\nAug 9 14:22:47 log2\nAug 9 14:22:47 log3\n"""

    with open(file, 'a') as f:
        f.write(data)

def modify_iis_file(file):
    """Create a iis content with an specific values"""

    data = '2020-11-19 22:48:39 206.175.82.5 - 208.201.133.173 GET /global/images/navlineboards.gif - 200 540 324 157 HTTP/1.0 Mozilla/4.0+(compatible;+MSIE+4.01;+Windows+95) USERID=CustomerA;+IMPID=01234 http://www.loganalyzer.net\n'
    with open(file, 'a') as f:
        f.write(data)

def modify_file(file, type, content):
    """ Modify a file to generate logs."""
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
        modify_mysqlLog_file(file)
    elif type == 'postgresql_log':
        modify_postgresqlLog_file(file)
    elif type == 'nmapg':
        modify_nmapg_file(file, content)
    elif type == 'djb-multilog':
        modify_djb_multilog_file(file, content)
    elif type == 'multi-line:3':
        modify_multi_line_file(file)
    elif type == 'iis':
        modify_iis_file(file)

def check_log_format_valid(cfg):
    """Check if Wazuh run correctly with the specified log formats.

    Ensure logcollector allows the specified log formats. Also, in the case of the manager instance, check if the API
    answer for localfile block coincides.

    Raises:
        TimeoutError: If the "Analyzing file" callback is not generated.
        AssertError: In the case of a server instance, the API response is different that the real configuration.
    """
    wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
    if cfg['log_format'] == 'eventchannel' or cfg['log_format'] == 'eventlog':
        log_callback = logcollector.callback_eventchannel_analyzing(cfg['location'])
    else:
        log_callback = logcollector.callback_analyzing_file(cfg['location'], prefix=prefix)
    wazuh_log_monitor.start(timeout=5, callback=log_callback, error_message=logcollector.GENERIC_CALLBACK_ERROR_ANALYZING_FILE)

def check_log_format_value_valid(conf):
    """
    Check if Wazuh runs correctly with the correct log format and content.
    Ensure logcollector allows the specified log formats.

    Raises:
        TimeoutError: If the "Analyzing file" callback is not generated.
    """

    wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)

    if conf['log_format'] not in log_format_windows_print_analyzing_info:
        if conf['log_format'] in log_format_not_print_reading_info:
            # Logs format that only shows when a specific file is read.

            log_callback = logcollector.callback_read_file(conf['log_format'], conf['location'], prefix=prefix)
            wazuh_log_monitor.start(timeout=5, callback=log_callback, error_message=logcollector.GENERIC_CALLBACK_ERROR_READING_FILE)

        elif conf['log_format'] == 'multi-line:3':
            # It is necessary to reorganize the content of the file to compare it with the generated output of the 'multiline' format.

            msg = ""
            with open(location, 'r') as file:
                for line in file:
                    msg += line.rstrip('\n')
                    msg += ' '
                log_callback = logcollector.callback_reading_file(conf['log_format'], msg.rstrip(' '), prefix=prefix)
                wazuh_log_monitor.start(timeout=5, callback=log_callback, error_message=logcollector.GENERIC_CALLBACK_ERROR_READING_FILE)
        else:
            # Verify that the content of the parsed file is equal to the output generated in the logs.
            with open(location, 'r') as f:
                lines = f.readlines()
                for line in lines:
                    log_callback = logcollector.callback_reading_file(conf['log_format'], line.rstrip('\n'), prefix=prefix)
                    wazuh_log_monitor.start(timeout=5, callback=log_callback, error_message=logcollector.GENERIC_CALLBACK_ERROR_READING_FILE)

    elif conf['log_format'] == 'iis':
        log_callback = logcollector.callback_read_file(conf['log_format'], conf['location'], prefix=prefix)
        wazuh_log_monitor.start(timeout=5, callback=log_callback, error_message=logcollector.GENERIC_CALLBACK_ERROR_READING_FILE)

def analyzing_invalid_value(conf):
    """
    Created to analyze the content of a file specific.
    Args:
        location (str): Path Read.
        format (str): format Type to analyze error message
    """

    with open(conf['location']) as log:
        line = log.readline()
        log_callback = logcollector.callback_invalid_format_value(line.rstrip('\n'), conf['log_format'], conf['location'], prefix)
        return log_callback

def check_log_format_value_invalid(conf):
    """
    Check if Wazuh fails because of an  log format content invalid.

    Raises:
       TimeoutError: If error callback are not generated.
   """

    wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)

    if conf['log_format'] not in log_format_windows_print_analyzing_info:
        log_callback = analyzing_invalid_value(conf)
        wazuh_log_monitor.start(timeout=5, callback=log_callback, error_message=logcollector.GENERIC_CALLBACK_ERROR)

def check_log_format_values(conf):

    if conf['valid_value']:
        check_log_format_valid(conf)
        modify_file(conf['location'], conf['log_format'], conf['valid_value'])
        check_log_format_value_valid(conf)
        file.remove_file(conf['location'])
    else:
        check_log_format_valid(conf)
        modify_file(conf['location'], conf['log_format'], conf['valid_value'])
        check_log_format_value_invalid(conf)
        file.remove_file(conf['location'])

def test_log_format(get_local_internal_options, get_configuration, configure_local_internal_options, configure_environment):
    """
    Check if Wazuh log format field of logcollector works properly.

    Ensure Wazuh component fails in case of invalid content file and works properly in case of valid log format values.

    Raises:
        TimeoutError: If expected callbacks are not generated.
    """

    conf = get_configuration['metadata']

    control_service('stop', daemon=LOGCOLLECTOR_DAEMON)
    file.truncate_file(LOG_FILE_PATH)

    if conf['valid_value']:
        # Analyze valid formats with valid content in Windows
        if sys.platform == 'win32':
            if conf['log_format'] == 'iis':
                create_file(iis_path, conf['log_format'])
                control_service('start', daemon=LOGCOLLECTOR_DAEMON)
                check_log_format_values(conf)
            else:
                control_service('start', daemon=LOGCOLLECTOR_DAEMON)
                check_log_format_valid(conf)
        else:
            # Analyze valid formats with valid content in Linux
            if conf['log_format'] == 'djb-multilog':
                create_file(filemultilog, conf['log_format'])
                control_service('start', daemon=LOGCOLLECTOR_DAEMON)
                check_log_format_values(conf)

            elif conf['log_format'] == 'nmapg':
                create_file(nmap_log, conf['log_format'])
                control_service('start', daemon=LOGCOLLECTOR_DAEMON)
                check_log_format_values(conf)
            else:
                create_file(location, conf['log_format'])
                control_service('start', daemon=LOGCOLLECTOR_DAEMON)
                check_log_format_values(conf)

    else:
        # Analyze valid formats with invalid content in Windows
        # Return Exception Error
        if sys.platform == 'win32':
            sb.CalledProcessError
        else:
        # Analyze valid formats with invalid content in Linux
            if conf['log_format'] == 'djb-multilog':
                create_file(filemultilog, conf['log_format'])
                control_service('start', daemon=LOGCOLLECTOR_DAEMON)
                check_log_format_values(conf)

            elif conf['log_format'] == 'nmapg':
                create_file(nmap_log, conf['log_format'])
                create_file(location, conf['log_format'])
                control_service('start', daemon=LOGCOLLECTOR_DAEMON)
                check_log_format_values(conf)
                file.remove_file(nmap_log)

            else:
                create_file(location, conf['log_format'])
                control_service('start', daemon=LOGCOLLECTOR_DAEMON)
                check_log_format_values(conf)
