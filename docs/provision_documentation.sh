#!/usr/bin/env bash

CURRENT_PATH="$( cd $(dirname $0) ; pwd -P )"
docker build -t wazuh-qa-documentation .
docker run -it --rm -p 8080:8080 wazuh-qa-documentation $(git branch --show-current)
