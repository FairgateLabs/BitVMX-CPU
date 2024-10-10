docker run -v %cd%:/data -it --name verifier verifier:latest sh -c /data/build.sh
docker rm verifier