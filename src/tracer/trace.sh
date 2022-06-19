#!/bin/bash
rm /tmp/trace.log
source /opt/intel/sgxsdk/environment
sgx-gdb --command=gdb_commands.txt --args $@ 
cp /tmp/trace.log .
