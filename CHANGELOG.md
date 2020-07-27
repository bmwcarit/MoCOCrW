# Changelog

All notable changes to this project will be documented in this file.

# Unreleased

## Changed

* Replace `explicit_bzero(3)` with `OPENSSL_cleanse(3)` to fix compilation on non-glibc systems. (see #75)
* Replaced manual calculation of hash digest length by library function in ECIES
* Move DigestTypes from openssl namespace to mococrw namespace

## Fixed

* Exception message in AESCipher (thrown if key has unexpected length)
* Install target of documentation
* Add error detection to utility::fromHex

## Added

* Examples for KDF, MAC, ECIES and EdDSA, and updated existing examples and documentation
* Compilable examples for:
  * KDF
  * MAC
  * ECIES
  * RSA en-/decryption
  * ECC en-/decryption
  * RSA signatures, ECDSA, EdDSA and Ed25519
  * RSA, ECC, Ed25519 and Ed448 key creation
  * CSR creation
  * CA creation
  * CSR signing
  * hash calculation
  * Symmetric en-/decryption (incl. authenticated encryption)

# Release 3.0.0
* Initial Release (starting at 3.0.0 to keep soversion in sync)
* Library now uses semantic versioning
* Updated documentation
* Increased soversion to 3.0
