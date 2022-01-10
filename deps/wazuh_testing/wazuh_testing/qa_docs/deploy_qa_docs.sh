#!/bin/bash

if (($# < 1))
then
  printf "Expected call:\n\n$0 <BRANCH> (TYPE) (MODULES)\n\nTest type and modules are optionals.\n";
  exit 1;
fi

branch_name=$1;
test_type=$2;
test_modules=${@:3};

docker build -t qa-docs:0.1 dockerfiles/

printf "Using $branch_name branch as test(s) input.\n";
if (($# == 1))
then
  printf "Parsing the whole tests directory.\n";
  docker run qa-docs:0.1 $branch_name
elif (($# == 2))
then
  printf "Parsing $test_type test type.\n";
  docker run qa-docs:0.1 $branch_name $test_type
else
  printf "Parsing $test_modules modules from $test_type.\n";
  docker run qa-docs:0.1 $branch_name $test_type $test_modules
fi
