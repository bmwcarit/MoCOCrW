FROM ubuntu:focal

# Install MoCOCrW dependencies (except OpenSSL)
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get -y --no-install-recommends install \
        ca-certificates \
        clang \
        cmake \
        g++ \
        googletest \
        libboost-all-dev \
        make \
        ninja-build \
        pkg-config \
        wget \
        && rm -rf /var/lib/apt/lists/*

# Verify that the OpenSSL dev package has not been installed inadvertently
RUN ! dpkg -s libssl-dev

# Build and install specific OpenSSL version
RUN wget -O openssl.tar.gz https://github.com/openssl/openssl/archive/OpenSSL_1_1_1-stable.tar.gz \
        && tar xf openssl.tar.gz --one-top-level --strip-components=1 \
        && cd openssl \
        && ./config -Wl,--enable-new-dtags,-rpath,'$(LIBRPATH)' \
        && make -j $(nproc) \
        && make install_sw \
        && cd .. \
        && rm -rf openssl
