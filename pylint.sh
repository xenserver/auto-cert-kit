#!/bin/sh
if [ $# -eq 0 ]
then
echo "ACK Code Violations:"
files=`find -not -path "./XenAPI/*" |
    egrep -e '\.(py)$$' -e 'plugins/autocertkit' |
    sort | uniq`
else
files="$1"
fi 

for file in $files
do
    echo "Running pylint on $file..."
    pylint --rcfile=pylint.rc $file
done
