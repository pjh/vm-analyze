#!/bin/bash

if [[ "$#" -eq "1" ]]; then
	fname=$1
else
	fname="debug.out"
fi

echo "split -d -n l/10 $fname $fname."
split -d -n l/10 $fname $fname.

exit 0
