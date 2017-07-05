#!/usr/bin/env bash
# jenkins build helper script for libosmo-netif.  This is how we build on jenkins.osmocom.org

if ! [ -x "$(command -v osmo-build-dep.sh)" ]; then
	echo "Error: We need to have scripts/osmo-deps.sh from http://git.osmocom.org/osmo-ci/ in PATH !"
	exit 2
fi


set -ex

base="$PWD"
deps="$base/deps"
inst="$deps/install"
export deps inst

mkdir "$deps" || true
rm -rf "$inst"

osmo-build-dep.sh libosmocore

"$deps"/libosmocore/contrib/verify_value_string_arrays_are_terminated.py $(find . -name "*.[hc]")

export PKG_CONFIG_PATH="$inst/lib/pkgconfig:$PKG_CONFIG_PATH"
export LD_LIBRARY_PATH="$inst/lib"

osmo-build-dep.sh libosmo-abis

set +x
echo
echo
echo
echo " =============================== libosmo-netif ==============================="
echo
set -x

autoreconf --install --force
./configure CFLAGS="-Werror" CPPFLAGS="-Werror"
$MAKE $PARALLEL_MAKE
$MAKE distcheck \
  || cat-testlogs.sh
