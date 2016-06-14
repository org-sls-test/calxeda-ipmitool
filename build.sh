#!/bin/sh

version=`grep -r CX_VERSION include/ipmitool/ipmi_cxoem.h | awk '{print $3}' | sed 's/"//g'`
mkdir release

echo "### 64bit version ###"
sudo apt-get install libssl-dev
./configure
make
tar -C src/ -zcvf release/ipmitool-1.8.11${version}.tar.gz ipmitool
make clean
sudo apt-get remove libssl-dev

echo "### 32bit version ###"
sudo apt-get install libssl-dev:i386 gcc-multilib
./configure --build=i686-pc-linux-gnu "CFLAGS=-m32" "CXXFLAGS=-m32" "LDFLAGS=-m32"
make
tar -C src/ -zcvf release/ipmitool-1.8.11${version}_i386.tar.gz ipmitool

return 0
