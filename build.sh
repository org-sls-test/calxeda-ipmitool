#!/bin/sh

mkdir release

./configure
make
cp src/ipmitool release/ipmitool
make clean

./configure --build=i686-pc-linux-gnu "CFLAGS=-m32" "CXXFLAGS=-m32" "LDFLAGS=-m32"
make
cp src/ipmitool release/ipmitool_32

return 0
