#!/bin/sh

mkdir release

echo "### 64bit version ###"
./configure
make
cp src/ipmitool release/ipmitool
make clean

echo "### 32bit version ###"
./configure --build=i686-pc-linux-gnu "CFLAGS=-m32" "CXXFLAGS=-m32" "LDFLAGS=-m32"
make
cp src/ipmitool release/ipmitool_32

return 0
