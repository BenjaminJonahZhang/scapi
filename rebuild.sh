git submodule init
git submodule update

# delete all existing containers
docker ps -a -q | xargs --no-run-if-empty docker rm -f
# delete all images
docker images -q | xargs --no-run-if-empty docker rmi -f
# build a fresh one
docker build --no-cache -t scapicryptobiu/scapi -f dockerfiles/DockerfileBuild .
