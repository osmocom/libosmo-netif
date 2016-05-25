#!/usr/bin/env bash

set -ex

rm -rf deps/install
mkdir deps || true
cd deps
osmo-deps.sh libosmocore

cd libosmocore
autoreconf --install --force
./configure --prefix=$PWD/../install
$MAKE $PARALLEL_MAKE install

cd ../
osmo-deps.sh libosmo-abis
cd libosmo-abis
autoreconf --install --force
PKG_CONFIG_PATH=$PWD/../install/lib/pkgconfig:$PKG_CONFIG_PATH ./configure --prefix=$PWD/../install  
PKG_CONFIG_PATH=$PWD/..//install/lib/pkgconfig:$PKG_CONFIG_PATH $MAKE $PARALLEL_MAKE install

cd ../../
autoreconf --install --force
PKG_CONFIG_PATH=$PWD/deps/install/lib/pkgconfig:$PKG_CONFIG_PATH ./configure
PKG_CONFIG_PATH=$PWD/deps/install/lib/pkgconfig:$PKG_CONFIG_PATH $MAKE $PARALLEL_MAKE
PKG_CONFIG_PATH=$PWD/deps/install/lib/pkgconfig:$PKG_CONFIG_PATH LD_LIBRARY_PATH=$PWD/deps/install/lib $MAKE distcheck