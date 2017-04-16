#!/bin/sh -e

TARGET="build"
DIST="dist"
DEST="$DIST/letslambda.zip"

test -d .env || (echo "missing virtualenv environement."; exit 1)

test ! -d "$TARGET" || rm -rf $TARGET
test ! -d "$DIST" || rm -rf $DIST
mkdir $TARGET
mkdir $DIST

cp -pdr .env/lib/python2.7/site-packages/* "$TARGET/"
cp -pdr .env/lib64/python2.7/site-packages/* "$TARGET/"
cp -pdr .env/src/acme/acme/acme* "$TARGET/"
cp -pd letslambda.py "$TARGET/"

rm -f "$DEST"
cd "$TARGET" && zip --recurse-paths -9 "../$DEST" ./
