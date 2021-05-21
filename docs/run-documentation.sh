#!/usr/bin/env bash

BRANCH=$1

cd /wazuh-qa
git pull
git checkout ${BRANCH}
pip install -r requirements.txt
cd deps/wazuh_testing
python3 setup.py install

mkdir -p /var/ossec/queue/vulnerabilities/dictionaries/  /var/ossec/etc/ /var/ossec/logs/archives /var/ossec/bin/ /tmp/wazuh-testing/

touch /tmp/wazuh-testing/test.log
echo "" > /var/ossec/queue/vulnerabilities/dictionaries/cpe_helper.json
echo "" > /var/ossec/etc/local_internal_options.conf
echo "" > /var/ossec/logs/archives/archives.log
echo "" > /var/ossec/bin/wazuh-control
echo -e '#!/bin/sh' > /var/ossec/bin/wazuh-control
chmod +x /var/ossec/bin/wazuh-control

cd /wazuh-qa
mkdocs serve -a 0.0.0.0:8080
