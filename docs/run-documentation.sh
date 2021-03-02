#!/usr/bin/env bash

cd /wazuh-qa/deps/wazuh_testing/
python setup.py install

mkdir -p /var/ossec/queue/vulnerabilities/dictionaries/  /var/ossec/etc/ /var/ossec/logs/archives

echo "" >>  /var/ossec/queue/vulnerabilities/dictionaries/cpe_helper.json
echo "" >>  /var/ossec/etc/local_internal_options.conf
echo "" >>  /var/ossec/logs/archives/archives.log

cd /wazuh-qa
mkdocs serve -a 0.0.0.0:8080