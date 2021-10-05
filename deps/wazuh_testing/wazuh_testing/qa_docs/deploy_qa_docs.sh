branch_name=$1

docker build -t qadocs/$branch_name:0.1 --build-arg BRANCH=$branch_name dockerfiles/
docker run qadocs/$branch_name:0.1
