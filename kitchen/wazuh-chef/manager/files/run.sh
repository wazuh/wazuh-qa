#!/bin/bash

development_agent_path="$COOKBOOKS_HOME/wazuh_agent/test/environments/development.json"
template=".template"
echo $COOKBOOKS_HOME

if [ -z "$1" ]
then
	distributions=( "ubuntu" "centos" )
else
	distributions=$1
fi

for dist in "${distributions[@]}"
do
	echo "Kitchen is creating the new instances with dist=$dist"
	kitchen create $dist

	echo "Getting Wazuh managers IPs to the agents"
	manager_ip="$(docker inspect --format '{{ .NetworkSettings.IPAddress }}' `docker ps | awk '{print $NF}' | grep  $dist | grep manager`)"


	cp "$development_agent_path$template" "$development_agent_path"

	echo "Assigning Wazuh managers IPs to the corresponding agents."
	sed -i 's/manager-client.wazuh-test.com//g' $development_agent_path
	sed -i 's/manager-master.wazuh-test.com/'${manager_ip}'/g' $development_agent_path


	echo "Kitchen is converging ..."
	kitchen converge $dist


	echo "Getting default things back"
	cp "$development_agent_path$template" "$development_agent_path"
done

echo "Kitchen is testing ..."
kitchen verify
