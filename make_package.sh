#!/bin/sh -e

. /etc/os-release
case "$ID" in
	"amzn")
		echo "Packaging..."
	;;
	"*")
		echo "An AWS Lambda function should only be packaged from an Amazon Linux to prevent broken shared library dependencies"
		exit
	;;
esac

TARGET="build"
DIST="dist"
DEST="$DIST/letslambda.zip"

test -d .env || (echo "missing virtualenv environement."; exit 1)

test ! -d "$TARGET" || rm -rf $TARGET
test ! -d "$DIST" || rm -rf $DIST
mkdir $TARGET $DIST

cp -pdr \
	$(find .env/lib64/python2.7/site-packages/ -maxdepth 1 -not -path .env/lib64/python2.7/site-packages/) \
	$(find .env/lib/python2.7/site-packages/ -maxdepth 1 -not -path .env/lib/python2.7/site-packages/) \
	"$TARGET/"
cp -pd letslambda.py "$TARGET/"

rm -f "$DEST"
cd "$TARGET" && zip --recurse-paths -9 "../$DEST" ./
