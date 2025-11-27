# CiVerLy in Docker

To build the docker image run the following command in the civerly
directory. Notice that this will take some time.
```
docker build -t civerly -f docker/Dockerfile .
```

To start a `sage` shell inside the container run:
```
docker run -it civerly
```
To start a `bash` shell inside the container run:
```
docker run -it --entrypoint bash civerly
```

To share the docker image, save it to a file:
```
docker save civerly > civerly.tar
```
This file can then be loaded again (on a different machine) with:
```
docker load < civerly.tar
```
