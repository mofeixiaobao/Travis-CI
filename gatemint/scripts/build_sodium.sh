#!/usr/bin/env bash
#set -e
#set -x

rootname="$(dirname "$PWD")"
#rootname=$(dirname "$dname")

if [ ! -d ${rootname}/libsodium ]; then
    mkdir -p ${rootname}/libsodium
    #sudo chown ${USER} ${rootname}/libsodium
fi

SODIUM_PATH=${rootname}/libsodium
if [ -f ${SODIUM_PATH}/include/sodium.h ] && [ -f ${SODIUM_PATH}/lib/libsodium.a ]; then
    echo "libsodium already installed"
    exit 0
fi

cd ${SODIUM_PATH}
srcpath=draft-irtf-cfrg-vrf-03
srcname="libsodium-"${srcpath}
libname=${srcname}".zip"

if [ ! -d ${SODIUM_PATH}/${srcname} ]; then
    curl https://codeload.github.com/gatechain/libsodium/zip/${srcpath} > ${SODIUM_PATH}/${libname}
    unzip ${libname}
fi

cd ${srcname} && \
		./autogen.sh && \
		./configure --disable-shared --prefix=${SODIUM_PATH} && \
		make install && \
		make clean


