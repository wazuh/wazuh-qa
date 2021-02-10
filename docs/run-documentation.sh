python /wazuh-qa/deps/wazuh_testing/setup.py install
cd /wazuh-qa
export PYTHONPATH=/wazuh-qa/deps/wazuh_testing

mkdir -p /var/ossec/queue/vulnerabilities/dictionaries/
echo "" >>  /var/ossec/queue/vulnerabilities/dictionaries/cpe_helper.json
mkdocs serve -a 0.0.0.0:8080