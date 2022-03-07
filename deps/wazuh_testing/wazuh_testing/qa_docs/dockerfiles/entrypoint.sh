#!/bin/bash

BRANCH="$1";
SHARED_VOL="$2"
CMD="${@:3}";

# Clone tests to be parsed as qa-docs input
mkdir /tests && cd /tests
echo "Cloning tests to parse from ${BRANCH} branch"
git clone https://github.com/wazuh/wazuh-qa --depth=1 -b ${BRANCH} &> /dev/null

# get run status
status=$?
# If not returned 0, exit
if [ $status -ne 0 ]
then
  echo "Could not download tests input from ${BRANCH} branch"
  exit 1
fi

/usr/local/bin/qa-docs -p /tests/wazuh-qa/tests --validate-parameters ${CMD}

# get run status
status=$?
# If not returned 0, exit
if [ $status -ne 0 ]
then
  exit 1
fi

# Start services
# If qa-docs will index the data, start ES
if [[ "$CMD" =~ .*"-i".* ]] || [[ "$CMD" =~ .*"-il".* ]];
then
   service elasticsearch start
fi
service wazuh-manager start

# Run qa-docs with the given args
echo "Running /usr/local/bin/qa-docs -p /tests/wazuh-qa/tests ${CMD}"
/usr/local/bin/qa-docs -p /tests/wazuh-qa/tests ${CMD}

# Move the documentation parsed to the shared dir
echo "Moving qa-docs output to shared directory: ${SHARED_VOL}/output"
rm -rf /qa_docs/output &> /dev/null
mv -f /tmp/qa_docs/output /qa_docs
