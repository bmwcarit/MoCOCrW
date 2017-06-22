#!/usr/bin/env bash

# Requirements:
# - SDKROOT set to the path of an unpacked MGU SDK.
BUILD_DIR="build"
SDK_BINPATH="opt/nativesysroot/usr/bin"
SDK_SUBPATH="$SDK_BINPATH/sdk/"
CMAKE_PATH="$SDKROOT/$SDK_SUBPATH/cmake"
MAKE_PATH="$SDKROOT/$SDK_SUBPATH/make"
CTEST_PATH="$SDKROOT/$SDK_BINPATH/carroot $SDKROOT/$SDK_BINPATH/ctest"
CTEST_ARGS="--output-on-failure -j $(nproc)"
CMAKE_ARGS="-DBUILD_TESTING=True\
    -DCMAKE_EXPORT_COMPILE_COMMANDS=ON"

if [ ! -e $CMAKE_PATH ]; then
  echo "[-] Can't find cmake in $CMAKE_PATH, check your sdk installation..."
  exit 1
fi
if [ ! -e $MAKE_PATH ]; then
  echo "[-] Can't find make in $MAKE_PATH, check your sdk installation..."
  exit 1
fi

if [ ! -d $BUILD_DIR ]; then
    echo "[+] Creating build environment in '$BUILD_DIR'"
        mkdir $BUILD_DIR
elif [ "$(ls -A $BUILD_DIR)" ]; then
    echo "[+] Cleaning old build environment"
    rm -rf $BUILD_DIR
fi
if [ ! -e $BUILD_DIR ]; then
  echo "[+] Creating build directory './$BUILD_DIR'"
  mkdir $BUILD_DIR
fi

echo "[+] Generating makefiles"
(cd build && $CMAKE_PATH $BUILD_TYPE $CMAKE_ARGS ..)
if [ $? -gt 0 ]; then
  echo "[-] Can't create build files in $BUILD_DIR"
  exit 1
fi
echo "[+] Building project with -j$(nproc)"
(cd build && $MAKE_PATH -j $(nproc))
if [ $? -gt 0 ]; then
  echo "[-] Failed to build project"
  exit 1
fi
echo "[+] Executing tests"
(cd build; $CTEST_PATH $CTEST_ARGS)
if [ $? -gt 0 ]; then
  echo "[-] Failed to run tests"
  exit 1
fi
