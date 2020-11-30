MoCOCrW
===================================================

(mo)dern (c)++ (o)penssl (cr)ypto (w)rapper library
===================================================

As part of our development efforts we noticed that there are cryptographic
primitives that are needed in many different situations. Unfortunately,
most of the libraries are only in C and the only library that implements all
the different algorithms/modes and primitives is OpenSSL.

OpenSSL is hard to use and does not integrate well in a C++14/17 development
environment. Consequently, we decided to provide a wrapping framework around
OpenSSL with the following goals in mind:
 * Translation of OpenSSL memory management into C++ memory management concepts
 * Good testability - in particular all calls to OpenSSL should be mockable
 * Extensive automatic testing
 * Easy to use end-user interface for common features

This library is the work-in-progress result of the above ideas.

## Support
We currently support OpenSSL 1.1.1 in the openssl1.1 branch. The support for
OpenSSL 1.0.\<x\> (in the master and the openssl1.0.2 branch) has been dropped. These
branches are **not** maintained anymore. The library is developed and tested mainly for
x86_64 and aarch64 targets with Linux. However, there is no general limitation to that.


The library provides end-user interfaces for:
 * X509 certificate processing
 * X509 certificate CA functionality
 * CRLs
 * RSA Encryption and Signatures
 * ECDSA Signatures
 * EdDSA Signatures
 * ECIES Encryption (according to IEEE 1363a-2004)
 * PBKDF2 and X963KDF Key derivation
 * HMAC
 * AES-CMAC (according to RFC 4493 for 128 and 256 bit keys)
 * AES Encryption (including GCM to support authenticated encryption with additional data)
 * SHA 1/2/3 Hashing

## Building

The library contains CMake build scripts. As a dependency, your build environment should
have development packages for the following libraries installed:
 * OpenSSL (1.1.1 branch)
 * Boost
 * gtest/gmock

In order to build the library with tests, do
```
$ mkdir build; cd build
build/$ cmake -DBUILD_TESTING=True ..
build/$ make
build/$ ctest . --output-on-failure
```

The bci.config file is used by our internal validation environment, please just ignore it.

## Installation / Usage / Packaging

MoCOCrW is prepared to be installed or packaged into an SDK. It also provides a cmake
exported target that you can use in your projects. A minimal example how to use this cmake
integration can be found in `tests/sdk`. This can also be used as an integration test if you
want to ship MoCOCrW with an SDK.

Unfortunately, there is not a lot of usage examples available right now. You may have a look
at the unit tests to see the API in action.

Most functionality is already documented in a doxygen style documentation in code.
More examples and a complete documentation will follow.

## Support / Comments

Support for this library will be provided on a best-effort basis. However, we encourage
you to submit bugs or contact us via github if there is an issue.

## Doxygen Documentation

In order to generate the doxygen documentation please follow the next steps:
on the project build directory run:

```
cmake -DBUILD_DOCUMENTATION=ON -DDOCUMENTATION_INSTALL_DESTINATION=/<path to doc folder> ..
make doc
```

If the option `DOCUMENTATION_INSTALL_DESTINATION` is omitted, the documentation will only be built
but not installed.

## Versioning and Releases
This library applies versioning similar to what is described at [semver.org](https://semver.org).
In addition, we are keeping soversion and library version in sync and will create major releases
even though it would not be necessary according to Semantic Versioning (e.g. due to break of ABI)
