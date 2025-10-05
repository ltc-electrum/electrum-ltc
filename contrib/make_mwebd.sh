#!/bin/bash

set -e

. "$(dirname "$0")/build_tools_util.sh" || (echo "Could not source build_tools_util.sh" && exit 1)

here="$(dirname "$(realpath "$0" 2> /dev/null || grealpath "$0")")"
CONTRIB="$here"
PROJECT_ROOT="$CONTRIB/.."

pkgname="mwebd"
info "Building $pkgname..."

(
    cd "$CONTRIB/mwebd"

    if [ "$BUILD_TYPE" = "wine" ] ; then
        # windows target
        CC=x86_64-w64-mingw32-gcc
        GOARCH=amd64
        GOOS=windows
        dlname=libmwebd-0.dll
    elif [ $(uname) == "Darwin" ]; then
        # macos target
        dlname=libmwebd.0.dylib
    else
        # linux target
        dlname=libmwebd.so.0
    fi
    export CC GOARCH GOOS

    mkdir -p dist
    PATH=/usr/local/go/bin:$PATH
    CGO_ENABLED=1 go build -buildmode=c-shared -ldflags="-s -w" -o dist/$dlname . || fail "Could not build $pkgname"
    cp -fpv dist/$dlname "$PROJECT_ROOT/electrum" || fail "Could not copy the $pkgname binary to its destination"
    info "$dlname has been placed in the inner 'electrum' folder."
    if [ -n "$DLL_TARGET_DIR" ] ; then
        cp -fpv dist/$dlname "$DLL_TARGET_DIR/" || fail "Could not copy the $pkgname binary to DLL_TARGET_DIR"
    fi
)
