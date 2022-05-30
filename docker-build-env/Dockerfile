FROM ubuntu:focal

# Install MoCOCrW dependencies (except OpenSSL)
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get -y --no-install-recommends install \
        ca-certificates \
        clang \
        clang-format-10 \
        cmake \
        g++ \
        git \
        googletest \
        libboost-all-dev \
        # libp11 engine
        libengine-pkcs11-openssl \
        # headers for p11 engine
        # TODO: this may not be necessary if we don't use libp11 directly (only though openssl)
        libp11-dev \
        # softhsm2 module
        libsofthsm2 \
        libssl-dev \
        make \
        ninja-build \
        # for pkcs11-tool which we use to create keys in token
        opensc \
        # p11-kit-modules allows loading of libp11 engine without having to edit openssl.cnf
        p11-kit-modules \
        pkg-config \
        wget \
        && rm -rf /var/lib/apt/lists/*
