#!/bin/sh

set -eu

files="$@"
thisdir=$(dirname "$0")

output=""

for file in "auto_cert_kit" "cpu_tests" "operations_tests" "storage_tests" "utils" "network_tests" "testbase" 
do
    echo "Running pylint on $file..."
    cd "kit"
    #An addition to use the same script in/out of the chroot
    pylint --rcfile=../pylint.rc --persistent=n "$file.py"
    #CMD used for the purposes of being inside the chroot
    out=$(pylint --rcfile=../pylint.rc --persistent=n "$file.py")
    cd "../"
    if [ "$out" ]
	then
	    echo $out 1>&2
	exit 1
	fi
done
