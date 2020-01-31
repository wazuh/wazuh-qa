#!/bin/bash

set -e

mkdir -p modules/wazuh

cd .. && cp -r `ls -A | grep -v "kitchen"` kitchen/modules/wazuh/

cd kitchen # Access kitchen folder


echo "Kitchen is creating the new instances"
kitchen create # creating new kitchen instances

echo "Getting Wazuh managers IPs to the agents"
manager_ip="$(docker inspect --format '{{ .NetworkSettings.IPAddress }}' `docker ps | awk '{print $NF}' | grep $PLATFORM | grep $RELEASE | grep manager`)"

echo "getting a copy of ./manifests/site.pp.template"
cp ./manifests/site.pp.template ./manifests/site.pp

echo "PRINT MANAGER IP"
echo $manager_ip

echo "PRINT MANIFEST SITE.PP"
cat ./manifests/site.pp

echo "Assigning Wazuh managers IPs to the corresponding agents."
sed -i 's/manager_ip/'${manager_ip}'/g' ./manifests/site.pp

echo "Setting the platform in the components names."
sed -i 's/platform/'$PLATFORM'/g' ./manifests/site.pp

echo "Setting the rlease in the components names."
sed -i 's/release/'$RELEASE'/g' ./manifests/site.pp

if [[ $PLATFORM == *"centos"* ]] || [[ $PLATFORM == *"amazon"* ]]; then
   echo "suite is a Centos one and requires OpenSSL to be installed. .. Installing .."
   kitchen exec $PLATFORM -c "sudo yum install -y openssl"
fi

echo "Kitchen is converging ..."
kitchen converge

echo "Kitchen is testing ..."
kitchen verify

echo "Kitchen is destroying"
kitchen destroy