# Configure test
import os

def pytest_addoption(parser):
  parser.addoption('--to_version', action='store', default='ERROR', help='Wazuh version to test files.')
  parser.addoption('--os', action='store', default='ERROR', help='OS version where wazuh was installed.')
  parser.addoption('--target', action='store', default='ERROR', help='Target to be tested.')

def pytest_configure(config):
  os.environ["to_version"] = config.getoption('to_version')
  os.environ["os"] = config.getoption('os')
  os.environ['target'] = config.getoption('target')