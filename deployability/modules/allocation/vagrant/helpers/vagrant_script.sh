#!/bin/bash

# Set the path to Vagrant directory
VAGRANT_DIR="/usr/local/bin"
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"

# Add Vagrant directory to PATH
export PATH=$PATH:$VAGRANT_DIR

# Check if an argument is provided
if [ $# -eq 0 ]
then
        echo "Usage: $0 [up | destroy | status | ...]"
        exit 1
fi

if [ $1 == "destroy" ]; then
        VAGRANT_CWD=$SCRIPT_DIR vagrant $1 -f
else
        VAGRANT_CWD=$SCRIPT_DIR vagrant $1
fi

exit 0
