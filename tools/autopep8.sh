#!/bin/sh
pwd0="$(dirname "$0")"
if [ $# -eq 0 ] ; then
    echo "Automated extra/missing whitespace code correction using autopep8"
    files=`find $pwd0/../ -not -path "$pwd0/../XenAPI/*" |
        egrep -e '\.(py)$$' -e 'plugins/autocertkit' |
        sort | uniq`
else
    files="$1"
fi 

for file in $files ; do
    echo "Running autopep8 on $file for whitespace changes only..."
    autopep8 -i $file
done
