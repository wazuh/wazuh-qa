#!/usr/bin/env bash

cp ../requirements.txt .
docker build -t  wazuh-qa-documentation .
rm ./requirements.txt
docker run -it --rm -v "$(dirname $(pwd))":/wazuh-qa -p 8080:8080 wazuh-qa-documentation
