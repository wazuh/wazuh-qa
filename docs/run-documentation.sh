python /wazuh-qa/deps/wazuh_testing/setup.py install
cd /wazuh-qa
export PYTHONPATH=/wazuh-qa/deps/wazuh_testing

mkdir -p /var/ossec/queue/vulnerabilities/dictionaries/
mkdir -p /var/ossec/etc/
echo "" >>  /var/ossec/queue/vulnerabilities/dictionaries/cpe_helper.json
echo "" >>  /var/ossec/etc/local_internal_options.conf

mkdocs serve -a 0.0.0.0:8080