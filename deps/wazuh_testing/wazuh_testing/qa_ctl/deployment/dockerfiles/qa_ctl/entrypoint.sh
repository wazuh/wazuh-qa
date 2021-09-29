#!/bin/bash

BRANCH="$1"
CONFIG_FILE_PATH="$2"
EXTRA_ARGS="${@:3}"

# Clone custom wazuh-qa repository branch
git clone https://github.com/wazuh/wazuh-qa --depth=1 -b ${BRANCH} &> /dev/null

# Install python dependencies not installed from
python3 -m pip install -r wazuh-qa/requirements.txt &> /dev/null

# Install Wazuh QA framework
cd wazuh-qa/deps/wazuh_testing &> /dev/null
python3 setup.py install &> /dev/null

# Run qa-ctl tool
/usr/local/bin/qa-ctl -c /qa_ctl/${CONFIG_FILE_PATH} ${EXTRA_ARGS}
