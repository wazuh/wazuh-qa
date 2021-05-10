# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import pytest
import sys
import subprocess as sb
import wazuh_testing.logcollector as logcollector

from os import remove, path
from wazuh_testing.tools import LOG_FILE_PATH
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.monitoring import LOG_COLLECTOR_DETECTOR_PREFIX, AGENT_DETECTOR_PREFIX, FileMonitor
from wazuh_testing.tools.file import truncate_file
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
    wazuh_configuration = 'ossec.conf'
    prefix = AGENT_DETECTOR_PREFIX

else:
    location = '/tmp/test.txt'
    wazuh_configuration = 'etc/ossec.conf'
    prefix = LOG_COLLECTOR_DETECTOR_PREFIX

parameters = [
#    {'LOCATION': f'{location}', 'LOG_FORMAT': 'json'},
#    {'LOCATION': f'{location}', 'LOG_FORMAT': 'json'},
    {'LOCATION': f'{location}', 'LOG_FORMAT': 'syslog'},
#    {'LOCATION': f'{location}', 'LOG_FORMAT': 'snort-full'},
#    {'LOCATION': f'{location}', 'LOG_FORMAT': 'squid'},
#    {'LOCATION': f'{location}', 'LOG_FORMAT': 'audit'},
#    {'LOCATION': f'{location}', 'LOG_FORMAT': 'audit'},
#    {'LOCATION': f'{location}', 'LOG_FORMAT': 'mysql_log'},
#    {'LOCATION': f'{location}', 'LOG_FORMAT': 'postgresql_log'},
#    {'LOCATION': f'{location}', 'LOG_FORMAT': 'nmapg'},
#    {'LOCATION': f'{location}', 'LOG_FORMAT': 'nmapg'},
#    {'LOCATION': '/var/log/current', 'LOG_FORMAT': 'djb-multilog'},
#    {'LOCATION': '/var/log/current', 'LOG_FORMAT': 'djb-multilog'},
#    {'LOCATION': f'{location}', 'LOG_FORMAT': 'multi-line:3'},
]

metadata = [
#    {'location': f'{location}', 'log_format': 'json', 'valid_value': False},
#    {'location': f'{location}', 'log_format': 'json', 'valid_value': True},
    {'location': f'{location}', 'log_format': 'syslog', 'valid_value': True},
#    {'location': f'{location}', 'log_format': 'snort-full', 'valid_value': True},
#    {'location': f'{location}', 'log_format': 'squid', 'valid_value': True},
#    {'location': f'{location}', 'log_format': 'audit', 'valid_value': False},
#    {'location': f'{location}', 'log_format': 'audit', 'valid_value': True},
#    {'location': f'{location}', 'log_format': 'mysql_log', 'valid_value': True},
#    {'location': f'{location}', 'log_format': 'postgresql_log', 'valid_value': True},
#    {'location': f'{location}', 'log_format': 'nmapg', 'valid_value': True},
#    {'location': f'{location}', 'log_format': 'nmapg', 'valid_value': False},
#    {'location': '/var/log/current', 'log_format': 'djb-multilog', 'valid_value': True},
#    {'location': '/var/log/current', 'log_format': 'djb-multilog', 'valid_value': False},
#    {'location': f'{location}', 'log_format': 'multi-line:3', 'valid_value': True},
]

if sys.platform == 'win32':
    parameters.append({'LOCATION': 'Security', 'LOG_FORMAT': 'eventlog'})
    parameters.append({'LOCATION': f'{location}', 'LOG_FORMAT': 'eventchannel'})
    parameters.append({'LOCATION': f'{location}', 'LOG_FORMAT': 'iis'})

    metadata.append({'location': 'Security', 'log_format': 'eventlog', 'valid_value': True})
    metadata.append({'location': f'{location}', 'log_format': 'eventchannel', 'valid_value': True})
    metadata.append({'location': f'{location}', 'log_format': 'iis', 'valid_value': True}),

configurations = load_wazuh_configurations(configurations_path, __name__, params=parameters, metadata=metadata)
configuration_ids = [f"{x['log_format'], x['valid_value']}" for x in metadata]

log_format_not_print_analyzing_info = ['eventlog', 'eventchannel', 'iis']

log_format_not_print_reading_info = ['audit', 'mysql_log', 'postgresql_log', 'nmapg']

# fixtures
@pytest.fixture(scope="module", params=configurations, ids=configuration_ids)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param

@pytest.fixture(scope="module")
def get_local_internal_options():
    """Get configurations from the module."""
    return local_internal_options

def create_file(file):
    """Create an empty file."""
    with open(file, 'a') as f:
        f.write("")

def remove_file(file):
    """ Remove a file created to testing."""
    os.remove(file)

def modify_json_file(file, type):
    """Create a json content with an specific values"""
    if type:
        data = """{"issue":22,"severity":1}\n"""
    else:
        data = """{"issue:22,"severity":1}"""
    with open(file, 'a') as f:
        f.write(data)

def modify_syslog_file(file):
    """Create a syslog content with an specific values"""
    data = """Apr 29 12:47:51 dev-branch systemd[1]: Starting\n"""

    with open(file, 'a') as f:
        f.write(data)

def modify_snort_file(file):
    """Create a snort content with an specific values"""
    data = """10/12-21:29:35.911089 [**] [1:0:0] TEST [**] [Priority: 0] {ICMP} 192.168.1.99 – > 192.168.1.103"""

    with open(file, 'a') as f:
        f.write(data)

def modify_squid_file(file):
    """Create a squid content with an specific values"""
    data = """902351618.864 440 120.65.1.1 TCP_MISS/304 110 GET http://www.webtrends.com:8005/Images/search.gif - DIRECT/www.webtrends.com -"""
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
        with open('/var/log/nmapg.log', 'a') as f:
            f.write("")
        data = """"nmap -T4 -A -v -oG /var/log/nmapg.log scanme.nmap.org"""
    else:
        data = """nmap -n -Pn -p 80 --open -sV -vvv --script banner,http-title -iR 1000\n"""

    with open(file, 'a') as f:
        f.write(data)

def modify_djb_multilog_file(file, type):
    """Create a djb-multilog content with an specific values"""

    if type:
        data = """@40000000590e30983973bda4 Message 1"""
    else:
        data = """@40000000590e30983973bda4 -e Error\n"""

    with open(file, 'a') as f:
        f.write(data)

def modify_multi_line_file(file):
    """Create a multi-line content with an specific values"""

    data = """Aug 9 14:22:47 log1\nAug 9 14:22:47 log2\nAug 9 14:22:47 log3\n"""

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
    elif type == 'nmap':
        modify_nmapg_file(file, content)
    elif type == 'djb-multilog':
        modify_djb_multilog_file(file, content)
    elif type == 'multi-line:3':
        modify_multi_line_file(file)

def check_log_format_valid(cfg):
    """Check if Wazuh run correctly with the specified log formats.

    Ensure logcollector allows the specified log formats. Also, in the case of the manager instance, check if the API
    answer for localfile block coincides.

    Raises:
        TimeoutError: If the "Analyzing file" callback is not generated.
        AssertError: In the case of a server instance, the API response is different that the real configuration.
    """
    wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)

    if cfg['log_format'] not in log_format_not_print_analyzing_info:
        log_callback = logcollector.callback_analyzing_file(cfg['location'], prefix=prefix)
        wazuh_log_monitor.start(timeout=5, callback=log_callback, error_message=logcollector.GENERIC_CALLBACK_ERROR_ANALYZING_FILE)

    elif cfg['log_format'] == 'djb-multilog':
        log_callback = logcollector.callback_monitoring_djb_multilog(cfg['location'], prefix=prefix)
        wazuh_log_monitor.start(timeout=5, callback=log_callback, error_message="The expected multilog djb log has not been produced")


def check_log_format_value_valid(conf):
    """
    Check if Wazuh runs correctly with the correct log format and content.
    Ensure logcollector allows the specified log formats.

    Raises:
        TimeoutError: If the "Analyzing file" callback is not generated.
    """

    wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)

    if conf['log_format'] not in log_format_not_print_analyzing_info:

        if conf['log_format'] in log_format_not_print_reading_info:
            log_callback = logcollector.callback_read_file(location, prefix=prefix)
            wazuh_log_monitor.start(timeout=5, callback=log_callback, error_message=logcollector.GENERIC_CALLBACK_ERROR_READING_FILE)

            if conf['log_format'] == 'nampg':
                remove_file('/var/log/nampg.log')

        elif conf['log_format'] == 'multi-line:3':
            msg = ""
            with open(location, 'r') as file:
                for line in file:
                    msg += line.strip()
                    msg += " "
                log_callback = logcollector.callback_reading_file(msg, prefix=prefix)
                wazuh_log_monitor.start(timeout=5, callback=log_callback, error_message=logcollector.GENERIC_CALLBACK_ERROR_READING_FILE)
        else:
            with open(location, 'r') as f:
                lines = f.readlines()

                # Strips the newline character
                for line in lines:
                    log_callback = logcollector.callback_reading_file(conf['log_format'], line.strip(), prefix=prefix)
                    wazuh_log_monitor.start(timeout=5, callback=log_callback, error_message=logcollector.GENERIC_CALLBACK_ERROR_READING_FILE)


def check_log_format_value_invalid(conf):
    """
    Check if Wazuh fails because of an  log format content invalid.

    Raises:
       TimeoutError: If error callback are not generated.
   """

    wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)

    if conf['log_format'] not in log_format_not_print_analyzing_info:
        with open(location, "r") as f:
            line = f.readline()
            if conf['log_format'] == 'json' or conf['log_format'] == 'djb-multilog':
                log_callback = logcollector.callback_invalid_format_value(line, conf['log_format'], location, prefix)
            elif conf['log_format'] == 'audit' or conf['log_format'] == 'nmapg':
                severity = 'ERROR'
                log_callback = logcollector.callback_invalid_format_value(line, conf['log_format'], location, prefix, severity)

            wazuh_log_monitor.start(timeout=5, callback=log_callback, error_message=logcollector.GENERIC_CALLBACK_ERROR)


def test_log_format(get_local_internal_options, get_configuration, configure_local_internal_options, configure_environment):
    """
    Check if Wazuh log format field of logcollector works properly.

    Ensure Wazuh component fails in case of invalid content file and works properly in case of valid log format values.

    Raises:
        TimeoutError: If expected callbacks are not generated.
    """

    conf = get_configuration['metadata']

    control_service('stop', daemon=LOGCOLLECTOR_DAEMON)
    truncate_file(LOG_FILE_PATH)

    if conf['valid_value']:
        if conf['log_format'] == 'djb-multilog':
            location_multilog = '/var/log/current'
            create_file(location_multilog)
            control_service('start', daemon=LOGCOLLECTOR_DAEMON)
            check_log_format_valid(conf)
            modify_file(location_multilog, conf['log_format'], conf['valid_value'])
            check_log_format_value_valid(conf)
            remove_file(location_multilog)

        elif sys.platform == 'win32':
            control_service('start', daemon=LOGCOLLECTOR_DAEMON)
            check_log_format_valid(conf)
        else:
            create_file(location)
            control_service('start', daemon=LOGCOLLECTOR_DAEMON)
            check_log_format_valid(conf)
            modify_file(location, conf['log_format'], conf['valid_value'])
            check_log_format_value_valid(conf)
            remove_file(location)

    else:
#        if sys.platform == 'win32':
#            expected_exception = ValueError
#        else:
#            expected_exception = sb.CalledProcessError

        if conf['log_format'] == 'djb-multilog':
            location_multilog = '/var/log/current'
            create_file(location_multilog)
            control_service('start', daemon=LOGCOLLECTOR_DAEMON)
            check_log_format_valid(conf)
            modify_file(location_multilog, conf['log_format'], conf['valid_value'])
            check_log_format_value_invalid(conf)
            remove_file(location_multilog)
        else:
            create_file(location)
            control_service('start', daemon=LOGCOLLECTOR_DAEMON)
            check_log_format_valid(conf)
            modify_file(location, conf['log_format'], conf['valid_value'])
            check_log_format_value_invalid(conf)
            remove_file(location)
