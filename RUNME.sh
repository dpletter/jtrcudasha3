#!/bin/sh

patchFiles () {
for i in $2
do
patch -p1 $1/$i $i.patch
done
}

JOHN_JUMBO_URL="http://www.openwall.com/john/g/john-1.7.9-jumbo-7.tar.gz"
JOHN_DIR=$(basename $JOHN_JUMBO_URL)
wget $JOHN_JUMBO_URL 
tar -xvf $JOHN_DIR

SRC_DIR=$(basename $JOHN_DIR .tar.gz)/src

patchFiles $SRC_DIR "Makefile john.c"

cp cuda_cryptsha3_fmt.c $SRC_DIR/
cp cuda_cryptsha3.h $SRC_DIR/
cp cryptsha3.cu $SRC_DIR/cuda/

cd $SRC_DIR && make linux-x86-64-cuda

