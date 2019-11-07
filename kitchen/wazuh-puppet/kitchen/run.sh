#!/bin/bash

set -e

mkdir -p modules/wazuh

cp -r ../files ./modules/wazuh/
cp -r ../templates/ ./modules/wazuh/
cp -r ../manifests/ ./modules/wazuh/

if [ -z "$1" ]
then
	suites_platforms=( "ubuntu" "centos" )
else
	suites_platforms=$1
fi

for suite in "${suites_platforms[@]}"
do

    if [[ $suite == *"ubuntu"* ]]; then
        platform = "ubuntu"

    elif [[ $suite == *"centos"* ]]; then
        platform = "centos"
	fi


    echo "$suite is selected"
    
    echo "Kitchen is creating the new instances"
    kitchen create $suite # creating new kitchen instances

    echo "Getting Wazuh managers IPs to the agents"
    manager_ip="$(docker inspect --format '{{ .NetworkSettings.IPAddress }}' `docker ps | awk '{print $NF}' | grep  $suite | grep manager`)"

    echo "getting a copy of ./manifests/site.pp.template"
    cp ./manifests/site.pp.template ./manifests/site.pp

    echo "Assigning Wazuh managers IPs to the corresponding agents."
    sed -i 's/manager_ip/'${manager_ip}'/g' ./manifests/site.pp

    echo "Setting the platform in the components names."
    sed -i 's/platform/'${platform}'/g' ./manifests/site.pp
    
	if [[ $suite == *"centos"* ]]; then
		echo "suite is a Centos one and requires OpenSSL to be installed. .. Installing .."
		kitchen exec $suite -c "sudo yum install -y openssl"
	fi

    echo "Kitchen is converging ..."
    kitchen converge $suite
done

echo "Kitchen is testing ..."
kitchen verify $suite

echo "Kitchen is destroying"
kitchen destroy $suite
