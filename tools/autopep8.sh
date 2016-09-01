#!/bin/sh
if [ $# -eq 0 ]
then
echo "Automated extra/missing whitespace code correction using autopep8"
files=`find ../ -not -path "../XenAPI/*" |
    egrep -e '\.(py)$$' -e 'plugins/autocertkit' |
    sort | uniq`
else
files="$1"
fi 

for file in $files
do
    echo "Running autopep8 on $file for whitespace changes only..."
    autopep8 -i $file
done
