# Changelog

All notable changes to this project will be documented in this file.

# Unreleased

## Changed

## Fixed

* CA Tests' SetUp was changed so that all the objects involved do not depend on time when
  construction of object is made. This led to problems where object of CA class had notBefore
  attribute set to greater value than CA's certificate's notBefore which should never happen.
  This subtle bug in test SetUp has greater chance of appearing when running in slower
  environments, e.g., qemu.

## Added

* Exceptions with better error messages were added in sanity check section of
  CertificateAuthority::_signCSR function. This provides better understanding of
  scenarios which we dont allow:
    - Issued certificate has greater notAfter attribute than CA's certificate (issued
      certificate's validity period should not exceed issuing certificate's validity
      period)
    - Case with the CA's notBefore being larger than the issued certificate's notBefore. This
      results in issued certificate that are valid *before* issuing certificate which
      should never happen.
  This is not a behavior change in the library in the sense that a certificate that was issued
  before won't be issued anymore. Certificates with these properties were already rejected
  by CertificateAuthority::signCSR but with a rather misleading and generic error message.
  This change just improves the error reporting.
* Clang-Format has been applied to the existing code-base of MoCOCrW and a `.clang-format`
  file has been included to format the code of of future PRs.
* A foundational PKCS#11 HSM interface, based OpenSSL's ENGINE API, has been introduced
  to MoCOCrW. Currently, the following functionality is supported:
    - Loading Public Keys
    - Loading Private Keys
    - Generating EC and RSA keypairs

# Release 4.1.1

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
