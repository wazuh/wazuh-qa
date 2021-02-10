python /wazuh-qa/deps/wazuh_testing/setup.py install
cd /wazuh-qa
export PYTHONPATH=/wazuh-qa/deps/wazuh_testing
mkdocs serve -a 0.0.0.0:8080