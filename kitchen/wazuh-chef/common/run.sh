#!/bin/bash

set -e

development_agent_path="../wazuh_agent/test/environments/development.json"
development_manager_path="../wazuh_manager/test/environments/development.json"
development_manager_path_master="../wazuh_manager/test/environments/development-master.json"

template=".template"


echo "Kitchen is creating the new instances"

kitchen create

echo "Getting Wazuh managers IPs to the agents"
manager_ip="$(docker inspect --format '{{ .NetworkSettings.IPAddress }}' `docker ps | awk '{print $NF}' | grep  $PLATFORM | grep $RELEASE | grep manager`)"

cp "$development_agent_path$template" "$development_agent_path"

echo "Assigning Wazuh managers IPs to the corresponding agents."
sed -i 's/manager-master.wazuh-test.com/'${manager_ip}'/g' $development_agent_path

echo "setting the manager registration and report IPs"

cp "$development_manager_path$template" "$development_manager_path"
sed -i 's/MANAGER_IP/'${manager_ip}'/g' $development_manager_path
cat $development_manager_path

cp "$development_manager_path_master$template" "$development_manager_path_master"
sed -i 's/MANAGER_IP/'${manager_ip}'/g' $development_manager_path_master
cat $development_manager_path_master


if [[ $PLATFORM == *"centos"* ]] || [[ $PLATFORM == *"amazon"* ]]; then
    echo "Platform is $PLATFORM and require OpenSSL to be installed. .. Installing .."
    kitchen exec $PLATFORM -c "sudo yum install -y openssl"
fi

echo "Kitchen is converging ..."
kitchen converge


echo "Getting default things back"
cp "$development_agent_path$template" "$development_agent_path"
cp "$development_manager_path$template" "$development_manager_path"
cp "$development_manager_path_master$template" "$development_manager_path_master"

echo "Kitchen is testing ..."
kitchen verify

echo "Kitchen is destroying"
kitchen destroy