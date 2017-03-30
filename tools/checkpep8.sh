#!/bin/sh
pwd0="$(dirname "$0")"
$pwd0/autopep8.sh
if [ "$(git diff)" ] ; then
    echo "checkpep8: Found violations, use tools/autopep8.sh to fix."
    echo "checkpep8: Expected fix:-"
    git diff
    exit 1
else
    echo "checkpep8: No violations found. Success"
fi
