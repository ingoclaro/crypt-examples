#!/bin/bash
java -cp ./java/lib/bcprov-jdk15on-148.jar:./java/lib/log4j-1.2.17.jar:./java/lib/commons-codec-1.7.jar:./java/dist/lib/crypt.jar Encrypt public_key.pem $1

