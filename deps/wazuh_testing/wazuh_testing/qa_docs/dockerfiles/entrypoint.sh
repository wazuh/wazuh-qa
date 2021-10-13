#!/bin/bash

BRANCH="$1";
TYPE="$2";
MODULES="${@:3}";

# Clone tests to be parsed as qa-docs input
mkdir ~/tests && cd ~/tests
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
cd /usr/local/lib/python3.8/dist-packages/wazuh_testing-4.3.0-py3.8.egg/wazuh_testing/qa_docs/search_ui
npm install

# Start services
service elasticsearch start && service wazuh-manager start

# Run qa-docs tool
if (($# == 1))
then
  /usr/local/bin/qa-docs -I ~/tests/wazuh-qa/tests -il qa-docs
elif (($# == 2))
then
  /usr/local/bin/qa-docs -I ~/tests/wazuh-qa/tests --types ${TYPE} -il qa-docs
else
  /usr/local/bin/qa-docs -I ~/tests/wazuh-qa/tests --types ${TYPE} --modules ${MODULES} -il qa-docs
fi
