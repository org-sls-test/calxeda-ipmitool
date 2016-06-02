#!/bin/sh

mkdir release

echo "### 64bit version ###"
sudo apt-get install libssl-dev
./configure
make
cp src/ipmitool release/ipmitool
make clean
sudo apt-get remove libssl-dev

echo "### 32bit version ###"
sudo apt-get install libssl-dev:i386 gcc-multilib
./configure --build=i686-pc-linux-gnu "CFLAGS=-m32" "CXXFLAGS=-m32" "LDFLAGS=-m32"
make
cp src/ipmitool release/ipmitool_32

return 0
