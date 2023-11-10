# Agent installation test
import pytest
import os
import json
import hashlib
import sys
import re

from helpers import tools
from subprocess import Popen, PIPE, check_output

# /////////////////////////////////////   TEST VARS  //////////////////////////////////////////

services = None
p = Popen(['/var/ossec/bin/wazuh-control', 'status'], stdin=PIPE, stdout=PIPE, stderr=PIPE)
if sys.version_info[0] < 3:
  services = p.stdout.read()
else:
  services = p.stdout
p.kill()


to_version = os.getenv('to_version')
system = os.getenv('os')
target = os.getenv('target')

assert_json_data = open("utils/asserts_description.json")
assert_description = json.load(assert_json_data)
assert_json_data.close()

daemons = tools.load_common_files_data(to_version, tools.daemons_path, target)
exceptions = tools.load_common_files_data(to_version, tools.exceptions_path, target)
conf_files = tools.load_common_files_data(to_version, tools.conffiles_path, target)

# /////////////////////////////////////   TESTS  //////////////////////////////////////////////

def test_check_version():
  version = check_output(["/var/ossec/bin/wazuh-control", "info", "-v"]).decode('utf-8').replace("v", "").replace("\n","")
  assert version == to_version, assert_description['version']['check_version']

# --------------------------------------------------------------------------------------------

'''
def test_check_service_status():
  assert 'active (running)' in service_status
'''
# --------------------------------------------------------------------------------------------

def test_check_process_modulesd():
  if 'wazuh-modulesd' in services:
    assert tools.get_key_value(daemons['data'], 'modulesd') in services, assert_description['process']['wazuh-modulesd']

# --------------------------------------------------------------------------------------------

def test_check_process_logcollector():
  if 'wazuh-logcollector' in services:
    assert tools.get_key_value(daemons['data'], 'logcollector') in services, assert_description['process']['wazuh-logcollector']

# --------------------------------------------------------------------------------------------

def test_check_process_syscheckd():
  if 'wazuh-syscheckd' in services:
    assert tools.get_key_value(daemons['data'], 'syscheckd') in services, assert_description['process']['wazuh-syscheckd']

# --------------------------------------------------------------------------------------------

def test_check_process_agentd():
  if 'wazuh-agentd' in services:
    assert tools.get_key_value(daemons['data'], 'agentd') in services, assert_description['process']['wazuh-agentd']

# --------------------------------------------------------------------------------------------

def test_check_process_execd():
  if 'wazuh-execd' in services:
    assert tools.get_key_value(daemons['data'], 'execd') in services, assert_description['process']['wazuh-execd']

# --------------------------------------------------------------------------------------------

def test_check_log_errors():
  f = open('/var/ossec/logs/ossec.log', 'r')
  print(f.read())
  f.close()
  expected_error = False

  with open('/var/ossec/logs/ossec.log', 'r') as f:
    for line in f.readlines():
      if 'ERROR' in line:
        for exception in tools.get_data_list(exceptions['data']):
          if re.search(exception, line):
            if exception == "wazuh-agentd: ERROR: (1218): Unable to send message to 'server': Connection refused":
              state = open('/var/ossec/var/run/wazuh-agentd.state', 'r')
              assert "status='connected'" in state.read(), assert_description['connection']['agent_connect_failure']
            print("Error detected as exception.")
            expected_error = True
            break
        assert expected_error == True, assert_description['error']['exception_not_detected'] + " in line {}".format(line)
      assert not 'CRITICAL' in line, assert_description['error']['critical'] + " in line {}".format(line)

# --------------------------------------------------------------------------------------------

def test_check_ossec_conf():
  f = open('/var/ossec/etc/ossec.conf', 'r')
  version_tokens = to_version.split(".")
  if system == "centos 5" and int(version_tokens[0]) <= 3 and int(version_tokens[1]) < 5:
    assert 'rhel 5' in f.read(), assert_description['files']['ossec_conf_OS_not_detected'] + ". It was expected to read rhel 5 in ossec.conf"
  elif system == 'amzn 1' or system == 'amzn 2018':
    file_content = f.read()
    assert 'amzn 2018' in file_content or 'amzn 1' in file_content, assert_description['files']['ossec_conf_OS_not_detected'] + ". It was expected to read amzn 2018 in ossec.conf"
  elif system == 'AIX 6':
    assert 'aix 6' in f.read(), assert_description['files']['ossec_conf_OS_not_detected'] + ". It was expected to read aix 6 in ossec.conf"
  else:
    assert system in f.read(), assert_description['files']['ossec_conf_OS_not_detected'] + ". It was expected to read {} in ossec.conf".format(system)
  f.close()

# --------------------------------------------------------------------------------------------

def test_connection_agent():
        f = open('/var/ossec/logs/ossec.log', 'r')
        assert "Connected to the server" in f.read(), assert_description['connection']['agent_connect_failure']
        f.close()
# --------------------------------------------------------------------------------------------