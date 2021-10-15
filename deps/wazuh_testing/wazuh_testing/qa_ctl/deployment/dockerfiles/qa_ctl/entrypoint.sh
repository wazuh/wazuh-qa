#!/bin/bash

BRANCH="$1"
CONFIG_FILE_PATH="$2"
EXTRA_ARGS="${@:3}"

# Download the custom branch of wazuh-qa repository
curl -Ls https://github.com/wazuh/wazuh-qa/archive/${BRANCH}.tar.gz | tar zx &> /dev/null && mv wazuh-* wazuh-qa

# Install python dependencies not installed from
python3 -m pip install -r wazuh-qa/requirements.txt &> /dev/null

# Install Wazuh QA framework
cd wazuh-qa/deps/wazuh_testing &> /dev/null
python3 setup.py install &> /dev/null

# Run qa-ctl tool
/usr/local/bin/qa-ctl -c /wazuh_qa_ctl/${CONFIG_FILE_PATH} ${EXTRA_ARGS}
