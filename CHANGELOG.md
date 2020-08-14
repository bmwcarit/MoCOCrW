# Changelog

All notable changes to this project will be documented in this file.

# Unreleased

## Changed

* Replace `explicit_bzero(3)` with `OPENSSL_cleanse(3)` to fix compilation on non-glibc systems. (see #75)
* Replaced manual calculation of hash digest length by library function in ECIES
* Improved error message when attempting to create an AES-GCM cipher with empty IV. (see #83)
* Move DigestTypes from openssl namespace to mococrw namespace. This is an ABI change!

## Fixed

* Exception message in AESCipher (thrown if key has unexpected length)
* Install target of documentation

## Added

* Examples for KDF, MAC, ECIES and EdDSA, and updated existing examples and documentation
* Expose `mococrw/bio.h` as public header to simplify interoperability with OpenSSL functions


# Release 3.0.0
* Initial Release (starting at 3.0.0 to keep soversion in sync)
* Library now uses semantic versioning
* Updated documentation
* Increased soversion to 3.0
