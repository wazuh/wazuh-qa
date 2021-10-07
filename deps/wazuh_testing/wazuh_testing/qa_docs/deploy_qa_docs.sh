#!/bin/sh
branch_name=$1

if [ "$#" -ne 1 ];
then
  echo "The branch where the tests to parse are located is missing:\n\n$0 BRANCH" >&2
  exit 1
fi

docker build -t qa-docs_base:0.2 -f dockerfiles/qa_docs_base.Dockerfile dockerfiles/
docker build -t qa-docs/$branch_name:0.2 --build-arg BRANCH=$branch_name -f dockerfiles/qa_docs_tool.Dockerfile dockerfiles/
docker run qa-docs/$branch_name:0.2
