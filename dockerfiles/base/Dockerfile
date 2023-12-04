FROM ubuntu:jammy

# Install MoCOCrW dependencies (except OpenSSL)
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get -y --no-install-recommends install \
        ca-certificates \
        clang \
        clang-format-11 \
        cmake \
        g++ \
        git \
        googletest \
        libgtest-dev \
        libgmock-dev \
        libboost-all-dev \
        libssl-dev \
        # For llvm-symbolizer (used by A/LSAN).
        # In particular, LLVM's symboliser is needed to print clearer
        # stack-traces for more accurate suppressions.
        llvm \
        make \
        ninja-build \
        pkg-config \
        wget \
        && rm -rf /var/lib/apt/lists/*
