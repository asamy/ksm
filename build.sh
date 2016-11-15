#!/bin/bash

CORES=`grep processor /proc/cpuinfo | wc -l`
MAKEOPT=$(($CORES + 1))
MAKE=make

$MAKE C=1 -j$MAKEOPT
if [[ "$?" -eq "0" ]]
then
	echo "Compilation successful.";
else
	echo "Compilation failed: $?";
fi

exit $?

