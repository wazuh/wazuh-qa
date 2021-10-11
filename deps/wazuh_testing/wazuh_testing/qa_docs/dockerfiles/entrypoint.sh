#!/bin/bash

BRANCH="$1";
TYPE="$2";
MODULES="${@:3}";

# Clone tests to be parsed as qa-docs input
mkdir tests && cd tests
git clone https://github.com/wazuh/wazuh-qa --depth=1 -b ${BRANCH} &> /dev/null

# Clone qa-docs
cd ~ && git clone https://github.com/wazuh/wazuh-qa

cd wazuh-qa/
git checkout 1864-qa-docs-fixes

# Install python dependencies not installed from
python3 -m pip install -r requirements.txt &> /dev/null

# Install Wazuh QA framework
cd deps/wazuh_testing &> /dev/null
python3 setup.py install &> /dev/null

# Install search-ui deps

# Start services
service elasticsearch start && service wazuh-manager start

# Run qa-docs tool
/usr/local/bin/qa-docs -I /tests/wazuh-qa/tests --types ${TYPE} --modules ${MODULES} -il qa-docs