### change toolchain to yours
export AR=arm-linux-gnueabihf-ar
export CC=arm-linux-gnueabihf-gcc
export CXX=arm-linux-gnueabihf-g++
export LINK=arm-linux-gnueabihf-g++

### add options, like --prefix=/opt/node-v0.8.x-pi/
./configure --without-snapshot --dest-cpu=arm --dest-os=linux
make
 
