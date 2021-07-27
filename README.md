<!--
  Title: Whaler
  Description: reverse docker images easily 
  Author: pegleg
  -->

# Whaler


Whaler is a Go program which is designed to reverse engineer docker images into the Dockerfile that created it.  It currently performs the following actions

  - Generates a Dockerfile from an Image
  - Searches added filenames for potential secret files
  - Extracts files that were added by the Docker ADD/COPY Instructions
  - It also displays misc. information such as ports open, the user it runs as and environment variables. 


### How to run it

The easiest way is to run the tool in docker container:

```bash
docker pull pegleg/whaler
docker run -t --rm -v /var/run/docker.sock:/var/run/docker.sock:ro pegleg/whaler -sV=1.36 nginx:latest
```

```bash
docker build --rm -t pegleg/whaler .
alias whaler="docker run -t --rm -v /var/run/docker.sock:/var/run/docker.sock:ro pegleg/whaler"
whaler -sV=1.36 nginx:latest
```

This tool will pull target docker image automatically. Parameter `-sV=1.36` is not always required.

### How to build it
Git clone the project into your $GOPATH/src directory and perform the following command
```bash
go get -u github.com/P3GLEG/Whaler
cd $GOPATH/src/github.com/P3GLEG/Whaler
go build .
```

### How to run it
```go
./Whaler
Usage of ./Whaler:
  -f string
    	File containing images to analyze seperated by line
  -filter
    	Filters filenames that create noise such as node_modules. Check ignore.go file for more details (default true)
  -sV string
    	Set the docker client ID to a specific version -sV=1.36
  -v	Print all details about the image
  -x	Save layers to current directory
```

