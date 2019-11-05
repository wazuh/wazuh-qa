#!/bin/bash
set -e

CHEF_SOURCE_BRANCH=$1
CHEF_TARGET_BRANCH=$2
QA_BRANCH=$3


cd $HOME/wazuh-qa/ && \
        git pull --all && \
        git checkout $QA_BRANCH && \
        git pull

cd $HOME && \
        git clone https://github.com/wazuh/wazuh-chef.git && \
        cd $HOME/wazuh-chef/ && \
        git checkout $CHEF_SOURCE_BRANCH && \
        git pull && \
        git checkout $CHEF_TARGET_BRANCH && \
        git pull && \
        git checkout $CHEF_SOURCE_BRANCH && \
        git merge $CHEF_SOURCE_BRANCH

cp -rf $HOME/wazuh-qa/kitchen/wazuh-chef/manager/files/* $HOME/wazuh-chef/cookbooks/wazuh_manager/
cp -rf $HOME/wazuh-qa/kitchen/wazuh-chef/manager/test/* $HOME/wazuh-chef/cookbooks/wazuh_manager/test/
cp -rf $HOME/wazuh-qa/kitchen/wazuh-chef/manager/test_environment/* $HOME/wazuh-chef/cookbooks/wazuh_manager/test/environments/
cp -rf $HOME/wazuh-qa/kitchen/wazuh-chef/agent/* $HOME/wazuh-chef/cookbooks/wazuh_agent/test/environments/


cd $HOME/wazuh-chef/cookbooks/wazuh_manager/ && \
        mkdir .kitchen

cd $HOME/wazuh-chef/cookbooks/wazuh_manager/ && \
        ls -ltrh
        chmod +x run.sh && \
        chmod +x clean.sh && \
        rm .kitchen.yml

tail -f /dev/null