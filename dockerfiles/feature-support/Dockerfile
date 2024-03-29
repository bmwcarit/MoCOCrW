FROM buildenv

ARG LIBP11_URL=https://github.com/OpenSC/libp11/releases/download/libp11-0.4.12/libp11-0.4.12.tar.gz
RUN mkdir /tmp/patches
COPY hsm-patches/0001-Introduce-generic-keypair-generation-interface-and-e.patch \
     dilithium-patches/0001-CMakeLists.txt-Add-BUILD_TESTING-compile-flag.patch     \
     dilithium-patches/0002-CMakeLists.txt-Enable-parallel-test-execution.patch     \
     dilithium-patches/0003-CMakeLists.txt-Enable-PIE-compilation-flag.patch        \
     dilithium-patches/0004-CMakeLists.txt-Add-UBSAN-and-ASAN-build-types.patch     \
     dilithium-patches/0005-CMakeLists.txt-Add-cmake-install-target.patch           \
     dilithium-patches/0006-CMakelists.txt-Add-stack-protector-strong-flag.patch    \
     dilithium-patches/0007-CMakeLists.txt-Change-target_compile_definition.patch   \
     dilithium-patches/0008-Add-function-for-pub-key-extraction.patch               \
     /tmp/patches/

# Install:
#  * MoCOCrW dependencies (except OpenSSL)
#  * libp11
#  * libdilithium
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get -y --no-install-recommends install \
    # for pkcs11-tool which we use to create keys in token
    opensc \
    # p11-kit-modules allows loading of libp11 engine without having to edit openssl.cnf
    p11-kit-modules \
    # softhsm2: includes both softhsm2-util and libsofthsm2
    softhsm2 \
    # libp11 needs this
    libtool && \
    rm -rf /var/lib/apt/lists/* && \

    # Build libp11
    mkdir -p /tmp/libp11 && \
    cd /tmp/libp11 && \
    wget "${LIBP11_URL}" && \
    tar xf libp11-0.4.12.tar.gz && \
    cd libp11-0.4.12 && \
    git apply /tmp/patches/0001-Introduce-generic-keypair-generation-interface-and-e.patch && \
    echo "Successfully patched libp11" && \
    autoreconf --verbose --install --force && \
    ./configure --enable-strict && \
    make -j"$(nproc)" && \
    make check && \
    make install && \
    rm -rf /tmp/libp11 && \

    # Build libdilithium
    mkdir /tmp/libdilithium && \
    cd /tmp/libdilithium && \
    git clone https://github.com/pq-crystals/dilithium && \
    cd dilithium && \
    git checkout 3e9b9f1412f6c7435dbeb4e10692ea58f181ee51 && \
    git apply /tmp/patches/0001-CMakeLists.txt-Add-BUILD_TESTING-compile-flag.patch   && \
    git apply /tmp/patches/0002-CMakeLists.txt-Enable-parallel-test-execution.patch   && \
    git apply /tmp/patches/0003-CMakeLists.txt-Enable-PIE-compilation-flag.patch      && \
    git apply /tmp/patches/0004-CMakeLists.txt-Add-UBSAN-and-ASAN-build-types.patch   && \
    git apply /tmp/patches/0005-CMakeLists.txt-Add-cmake-install-target.patch         && \
    git apply /tmp/patches/0006-CMakelists.txt-Add-stack-protector-strong-flag.patch  && \
    git apply /tmp/patches/0007-CMakeLists.txt-Change-target_compile_definition.patch && \
    git apply /tmp/patches/0008-Add-function-for-pub-key-extraction.patch             && \
    mkdir build && \
    cd build && \
    cmake -GNinja .. -DBUILD_TESTING=ON&& \
    ninja && \
    ctest -j"$(nproc)" && \
    ninja install && \
    cd / && \
    rm -rf /tmp/libdilithium && \
    rm -rf /tmp/patches

