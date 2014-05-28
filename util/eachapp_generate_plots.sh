#!/bin/bash

measurementsdir="./measurement_results"
script="./generate_plots.py"

if [[ "$#" -ne "1" ]]; then
	echo "usage: $0 ${measurementsdir}/somedir"
	exit 1
fi

resultsdir="$1"

for file in `ls ${resultsdir}`; do
	dirname="${resultsdir}/${file}"
	if [[ -d ${dirname} ]]; then
		outfile="debug.${file}.out"
		echo "Generating plots for ${dirname}"
		#echo "time ${script} ${dirname} &> ${outfile}"
		time ${script} ${dirname} &> ${outfile}
		tail -n 1 ${outfile}
		echo ""
	fi
done

exit 0
