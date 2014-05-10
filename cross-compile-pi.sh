### change toolchain to yours
export AR=arm-bcm2708hardfp-linux-gnueabi-ar
export CC=arm-bcm2708hardfp-linux-gnueabi-gcc
export CXX=arm-bcm2708hardfp-linux-gnueabi-g++
export LINK=arm-bcm2708hardfp-linux-gnueabi-g++

### add options, like --prefix=/opt/node-v0.8.x-pi/
./configure --without-snapshot --dest-cpu=arm --dest-os=linux --prefix=/opt/node-v0.8.x-pi/

make && make install
 
