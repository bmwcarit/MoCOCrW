FROM buildenv

# Install MoCOCrW dependencies (except OpenSSL)
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get -y --no-install-recommends install \
        # for pkcs11-tool which we use to create keys in token
        opensc \
        # p11-kit-modules allows loading of libp11 engine without having to edit openssl.cnf
        p11-kit-modules \
        # softhsm2: includes both softhsm2-util and libsofthsm2
        softhsm2 \
        # libp11 needs this
        libtool \
        && rm -rf /var/lib/apt/lists/*

# Install patched libp11
ARG LIBP11_URL=https://github.com/OpenSC/libp11/releases/download/libp11-0.4.12/libp11-0.4.12.tar.gz
RUN mkdir /tmp/libp11
ADD hsm-patches/0001-Introduce-generic-keypair-generation-interface-and-e.patch /tmp/libp11
RUN cd /tmp/libp11 && \
    wget $LIBP11_URL && \
    tar xf libp11-0.4.12.tar.gz && \
    cd libp11-0.4.12 && \
    git apply /tmp/libp11/0001-Introduce-generic-keypair-generation-interface-and-e.patch && \
    echo "Successfully patched libp11" && \
    autoreconf --verbose --install --force && \
    ./configure --enable-strict && \
    make -j$(nproc) && \
    make check && \
    make install && \
    rm -rf /tmp/libp11

# Install patched libdilithium
RUN mkdir /tmp/libdilithium
ADD dilithium-patches/0001-Add-code-to-enable-cmake-to-install-static-libraries.patch /tmp/libdilithium
ADD dilithium-patches/0002-CMakeLists-Change-target_compile_definition-to-PRIVA.patch /tmp/libdilithium
ADD dilithium-patches/0003-Add-function-for-pub-key-extraction.patch                  /tmp/libdilithium
RUN cd /tmp/libdilithium && \
    git clone https://github.com/pq-crystals/dilithium && \
    cd dilithium && \
    git apply /tmp/libdilithium/0001-Add-code-to-enable-cmake-to-install-static-libraries.patch && \
    git apply /tmp/libdilithium/0002-CMakeLists-Change-target_compile_definition-to-PRIVA.patch && \
    git apply /tmp/libdilithium/0003-Add-function-for-pub-key-extraction.patch                  && \
    mkdir build && \
    cd build && \
    cmake -GNinja .. && \
    ninja && \
    ninja install && \
    cd / && \
    rm -rf /tmp/libdilithium

