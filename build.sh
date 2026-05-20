#!/bin/bash

docker run --rm -itd syscap_test

go generate 

go build -o syscap .

docker ps