# Manager installation test
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

'''
p = Popen(['systemctl', 'status', 'wazuh-manager'], stdin=PIPE, stdout=PIPE, stderr=PIPE)
service_status = p.stdout.read()
p.kill()
'''

assert_json_data = open("utils/asserts_description.json")
assert_description = json.load(assert_json_data)
assert_json_data.close()

to_version = os.getenv('to_version')
system = os.getenv('os')
target = 'manager'

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

def test_check_process_clusterd():
  if 'wazuh-clusterd' in services:
    assert tools.get_key_value(daemons['data'], 'clusterd') in services, assert_description['process']['wazuh-clusterd']

# --------------------------------------------------------------------------------------------

def test_check_process_modulesd():
  if 'wazuh-modulesd' in services:
    assert tools.get_key_value(daemons['data'], 'modulesd') in services, assert_description['process']['wazuh-modulesd']

# --------------------------------------------------------------------------------------------

def test_check_process_monitord():
  if 'wazuh-monitord' in services:
     assert tools.get_key_value(daemons['data'], 'monitord') in services, assert_description['process']['wazuh-monitord']

# --------------------------------------------------------------------------------------------

def test_check_process_logcollector():
  if 'wazuh-logcollector' in services:
    assert tools.get_key_value(daemons['data'], 'logcollector') in services, assert_description['process']['wazuh-logcollector']

# --------------------------------------------------------------------------------------------

def test_check_process_remoted():
  if 'wazuh-remoted' in services:
     assert tools.get_key_value(daemons['data'], 'remoted') in services, assert_description['process']['wazuh-remoted']

# --------------------------------------------------------------------------------------------

def test_check_process_syscheckd():
  if 'wazuh-syscheckd' in services:
    assert tools.get_key_value(daemons['data'], 'syscheckd') in services, assert_description['process']['wazuh-syscheckd']

# --------------------------------------------------------------------------------------------

def test_check_process_analysisd():
  if 'wazuh-analysisd' in services:
    assert tools.get_key_value(daemons['data'], 'analysisd') in services, assert_description['process']['wazuh-analysisd']

# --------------------------------------------------------------------------------------------

def test_check_process_maild():
  if 'wazuh-maild' in services:
    assert tools.get_key_value(daemons['data'], 'maild') in services, assert_description['process']['wazuh-maild']

# --------------------------------------------------------------------------------------------

def test_check_process_execd():
  if 'wazuh-execd' in services:
    assert tools.get_key_value(daemons['data'], 'execd') in services, assert_description['process']['wazuh-execd']

# --------------------------------------------------------------------------------------------

def test_check_process_wazuhdb():
  if 'wazuh-db' in services:
    assert tools.get_key_value(daemons['data'], 'wazuhdb') in services, assert_description['process']['wazuh-db']

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
            print("Error detected as exception.")
            expected_error = True
            break
        assert expected_error == True, assert_description['error']['exception_not_detected']
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
  else:
    assert system in f.read(), assert_description['files']['ossec_conf_OS_not_detected'] + ". It was expected to read {} in ossec.conf".format(system)
  f.close()

# --------------------------------------------------------------------------------------------

def test_connection_manager():
        f = open('/var/ossec/logs/alerts/alerts.log', 'r')
        assert "Wazuh agent started." in f.read(), assert_description['connection']['agent_start_failure']
        f.close()

# --------------------------------------------------------------------------------------------