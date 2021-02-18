#!/usr/bin/env bash

docker build -t  wazuh-qa-documentation .
docker run -it --rm -v "$(dirname $(pwd))":/wazuh-qa -p 8080:8080 wazuh-qa-documentation