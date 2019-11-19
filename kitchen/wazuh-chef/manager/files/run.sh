#!/bin/bash

set -e

development_agent_path="../wazuh_agent/test/environments/development.json"
development_manager_path="../wazuh_manager/test/environments/development.json"
development_manager_path_master="../wazuh_manager/test/environments/development-master.json"

template=".template"

if [ -z "$1" ]
then
        suites_platforms=( "ubuntu" "centos" )
else
        suites_platforms=$1
fi

for suite in "${suites_platforms[@]}"
do
        echo "Kitchen is creating the new instances with dist=$suite"
        kitchen create $suite

        if [[ ${suite} != *"suite2"* ]];then # If suite is suite 1 and so it contains a manager and agent.

                echo "Getting Wazuh managers IPs to the agents"
                manager_ip="$(docker inspect --format '{{ .NetworkSettings.IPAddress }}' `docker ps | awk '{print $NF}' | grep  $suite | grep manager`)"
                echo $manager_ip

                cp "$development_agent_path$template" "$development_agent_path"

                echo "Assigning Wazuh managers IPs to the corresponding agents."
                sed -i 's/manager-client.wazuh-test.com//g' $development_agent_path
                sed -i 's/manager-master.wazuh-test.com/'${manager_ip}'/g' $development_agent_path

                echo "setting the manager registration and report IPs"

                cp "$development_manager_path$template" "$development_manager_path"
                sed -i 's/MANAGER_IP/'${manager_ip}'/g' $development_manager_path
                cat $development_manager_path

                cp "$development_manager_path_master$template" "$development_manager_path_master"
                sed -i 's/MANAGER_IP/'${manager_ip}'/g' $development_manager_path_master
                cat $development_manager_path_master
        fi
        echo "Kitchen is converging ..."

        if [[ $suite == *"centos"* ]]; then
                echo "suite is a centos and require OpenSSL to be installed. .. Installing .."
                kitchen exec $suite -c "sudo yum install -y openssl"
        fi

        kitchen converge $suite


        echo "Getting default things back"
        cp "$development_agent_path$template" "$development_agent_path"
        cp "$development_manager_path$template" "$development_manager_path"
        cp "$development_manager_path_master$template" "$development_manager_path_master"

done

echo "Kitchen is testing ..."
kitchen verify $suite

echo "Kitchen is destroying"
kitchen destroy $suite