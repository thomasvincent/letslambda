#!/bin/sh -e

TARGET="tmp"

test -d .env || (echo "missing virtualenv environement."; exit 1)

test ! -d "$TARGET" || rm -rf $TARGET
mkdir $TARGET

cp -pdr .env/lib/python2.7/site-packages/* "$TARGET/"
cp -pdr .env/lib64/python2.7/site-packages/* "$TARGET/"
cp -pdr .env/src/acme/acme/acme* "$TARGET/"

cd "$TARGET" && zip --recurse-paths -9 ../letslambda.zip ./
