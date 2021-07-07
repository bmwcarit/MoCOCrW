# Changelog

All notable changes to this project will be documented in this file.

# Unreleased

## Changed

## Fixed

* CertificateAuthority now copies the subject of the CA directly into the
  issuer field of the issued certificate. This resolves problems around
  different orders of items in the underlying distinguished name. This fixes
  issue #95. The DistinguishedName object is still not order-aware when loading
  a DN from OpenSSL. This is to be fixed in a later step.
* X509Certificate::signCSR doesn't validate the certificate at the current
  system time anymore but at certificate's notBefore and notAfter dates.
  This fixes issue #96 by allowing to sign past and future certificates but
  also ensures that the certificate's validity period does not exceed the
  validity bounds of the issuing certificate.

## Added

# Release 4.1.0

Support for AES-CMAC has been added (see `mac-example.cpp` for sample usage),
as well as some minor changes listed below.

## Changed

* Remove wrapper `openssl::_EVP_PKEY_CTX_get_rsa_oaep_label`. This is
  technically an ABI break, but since the wrappers are not considered part of
  the public API, we do not bump the SOVERSION for this.
* Improve error message in MoCOCrWException that is thrown in case of invalid
  signature validation.

## Added

* Support for AES-CMAC with key lengths of 128 and 256 bit.

# Release 4.0.0

Multiple (self-contained) example programs have been added to illustrate the features of this
libary. Otherwise, just smaller clean up tasks.

As part of the clean up, the `DigestTypes` enum has been moved from the openssl namespace into
the mococrw namespace. A `using` statement  was added to make this backwards-compatible API-wise.
It is, however, an ABI change. Thus, this is a new major version release.

## Details

### Changed

* Replace `explicit_bzero(3)` with `OPENSSL_cleanse(3)` to fix compilation on non-glibc systems. (see #75)
* Replaced manual calculation of hash digest length by library function in ECIES
* Improved error message when attempting to create an AES-GCM cipher with empty IV. (see #83)
* Move DigestTypes from openssl namespace to mococrw namespace. This is an ABI change!
* Add error detection to utility::fromHex (This changes the behaviour of fromHex as it will throw
errors on invalid string from now on.)

### Fixed

* Exception message in AESCipher (thrown if key has unexpected length)
* Install target of documentation
* Fix toggling stream cipher test when encrypting short messages

### Added

* Examples for KDF, MAC, ECIES and EdDSA, and updated existing examples and documentation
* Expose `mococrw/bio.h` as public header to simplify interoperability with OpenSSL functions
* Compilable examples for:
  * KDF
  * MAC
  * ECIES
  * RSA en-/decryption
  * ECC en-/decryption
  * RSA signatures, ECDSA, EdDSA
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
