/*
 * #%L
 * %%
 * Copyright (C) 2022 BMW Car IT GmbH
 * %%
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * #L%
 */
#pragma once

#include <chrono>
#include <ctime>
#include <limits>
#include <memory>
#include <vector>
#include "boost/format.hpp"

#include "openssl_lib.h"
#include "util.h"

namespace mococrw
{
/**
 * Enum for the digest types that can be used in signatures
 * or hash computations.
 */
enum class DigestTypes {
    SHA1,
    SHA256,
    SHA384,
    SHA512,
    SHA3_256,
    SHA3_384,
    SHA3_512,
    NONE = std::numeric_limits<int>::max()
};

/**
 * @brief Enum for the cipher types that can be used for CMAC computations
 */
enum class CmacCipherTypes {
    AES_CBC_128,
    AES_CBC_256,
};

namespace openssl
{
using DigestTypes = mococrw::DigestTypes;
using CmacCipherTypes = mococrw::CmacCipherTypes;

/**
 * Template to wrap OpenSSLs "_free" functions
 * into a functor so that a std::unique_ptr
 * can use them.
 */
template <class P, void(Func)(P *)>
struct SSLDeleter
{
    template <class T>
    void operator()(T *ptr) const noexcept
    {
        if (ptr) {
            Func(ptr);
        }
    }
};

/**
 * Like SSLDeleter, but takes into account the return type
 * in the definitions of the "_free" functions.
 *
 * We could have modified SSLDeleter to take arbitrary return
 * types, but this might result in an unwanted ABI change.
 */
template <class R, class P, R(Func)(P *)>
struct SSLRetDeleter
{
    template <class T>
    void operator()(T *ptr) const noexcept
    {
        if (ptr) {
            Func(ptr);
        }
    }
};

/**
 * Template to wrap the OpenSSL_free function
 * into a functor so that a std::unique_ptr
 * can use them.
 */
template <class P>
struct SSLFree
{
    void operator()(P *ptr)
    {
        if (ptr) {
            lib::OpenSSLLib::SSL_OPENSSL_free(ptr);
        }
    }
};

/**
 * An Exception for OpenSSL errors.
 *
 * This exception is thrown by all methods when an OpenSSL error occurs.
 */
class OpenSSLException final : public std::exception
{
public:
    template <class StringType>
    explicit OpenSSLException(StringType &&message) : _message{std::forward<StringType>(message)}
    {
    }

    /**
     * Generate an exception with the defalt OpenSSL error-string
     * as message.
     *
     */
    OpenSSLException();

    const char *what() const noexcept override { return _message.c_str(); }

    /**
     * The following functions enable fine-tuned error handling via sub-library and reason
     * information
     */
    std::string getLib() const { return _library; };
    std::string getReason() const { return _reason; };

private:
    static std::string generateOpenSSLErrorString(unsigned long error);
    std::string _message;
    std::string _library;
    std::string _reason;
};

/*
 * Wrap all the pointer-types returned by openssl.
 */
using SSL_EC_KEY_Ptr =
        std::unique_ptr<EC_KEY, SSLDeleter<EC_KEY, lib::OpenSSLLib::SSL_EC_KEY_free>>;

using SSL_EVP_PKEY_Ptr =
        std::unique_ptr<EVP_PKEY, SSLDeleter<EVP_PKEY, lib::OpenSSLLib::SSL_EVP_PKEY_free>>;
using SSL_EVP_PKEY_SharedPtr = utility::SharedPtrTypeFromUniquePtr<SSL_EVP_PKEY_Ptr>;

using SSL_EVP_PKEY_CTX_Ptr =
        std::unique_ptr<EVP_PKEY_CTX,
                        SSLDeleter<EVP_PKEY_CTX, lib::OpenSSLLib::SSL_EVP_PKEY_CTX_free>>;
using SSL_EVP_PKEY_CTX_SharedPtr = utility::SharedPtrTypeFromUniquePtr<SSL_EVP_PKEY_CTX_Ptr>;

using SSL_PKCS8_PRIV_KEY_INFO_Ptr = std::unique_ptr<
        PKCS8_PRIV_KEY_INFO,
        SSLDeleter<PKCS8_PRIV_KEY_INFO, lib::OpenSSLLib::SSL_PKCS8_PRIV_KEY_INFO_free>>;
using SSL_PKCS8_PRIV_KEY_INFO_SharedPtr =
        utility::SharedPtrTypeFromUniquePtr<SSL_PKCS8_PRIV_KEY_INFO_Ptr>;


using EVP_MAC_CTX_Ptr =
        std::unique_ptr<EVP_MAC_CTX, SSLDeleter<EVP_MAC_CTX, lib::OpenSSLLib::EVP_MAC_CTX_free>>;
using EVP_MAC_CTX_SharedPtr = utility::SharedPtrTypeFromUniquePtr<EVP_MAC_CTX_Ptr>;

using EVP_MAC_Ptr = std::unique_ptr<EVP_MAC, SSLDeleter<EVP_MAC, lib::OpenSSLLib::EVP_MAC_free>>;
using EVP_MAC_SharedPtr = utility::SharedPtrTypeFromUniquePtr<EVP_MAC_Ptr>;

using OSSL_LIB_CTX_Ptr =
        std::unique_ptr<OSSL_LIB_CTX, SSLDeleter<OSSL_LIB_CTX, lib::OpenSSLLib::OSSL_LIB_CTX_free>>;
using OSSL_LIB_CTX_SharedPtr = utility::SharedPtrTypeFromUniquePtr<OSSL_LIB_CTX_Ptr>;

using SSL_CMAC_CTX_Ptr =
        std::unique_ptr<CMAC_CTX, SSLDeleter<CMAC_CTX, lib::OpenSSLLib::SSL_CMAC_CTX_free>>;
using SSL_CMAC_CTX_SharedPtr = utility::SharedPtrTypeFromUniquePtr<SSL_CMAC_CTX_Ptr>;

using SSL_X509_REQ_Ptr =
        std::unique_ptr<X509_REQ, SSLDeleter<X509_REQ, lib::OpenSSLLib::SSL_X509_REQ_free>>;
using SSL_X509_REQ_SharedPtr = utility::SharedPtrTypeFromUniquePtr<SSL_X509_REQ_Ptr>;

using SSL_X509_NAME_Ptr =
        std::unique_ptr<X509_NAME, SSLDeleter<X509_NAME, lib::OpenSSLLib::SSL_X509_NAME_free>>;
using SSL_X509_NAME_SharedPtr = utility::SharedPtrTypeFromUniquePtr<SSL_X509_NAME_Ptr>;

using SSL_BIO_Ptr = std::unique_ptr<BIO, SSLDeleter<BIO, lib::OpenSSLLib::SSL_BIO_free_all>>;
using SSL_BIO_SharedPtr = utility::SharedPtrTypeFromUniquePtr<SSL_BIO_Ptr>;

using SSL_EVP_MD_CTX_Ptr =
        std::unique_ptr<EVP_MD_CTX,
                        SSLDeleter<EVP_MD_CTX, lib::OpenSSLLib::SSL_EVP_MD_CTX_destroy>>;
using SSL_EVP_MD_CTX_SharedPtr = utility::SharedPtrTypeFromUniquePtr<SSL_EVP_MD_CTX_Ptr>;

using SSL_X509_Ptr = std::unique_ptr<X509, SSLDeleter<X509, lib::OpenSSLLib::SSL_X509_free>>;
using SSL_X509_SharedPtr = utility::SharedPtrTypeFromUniquePtr<SSL_X509_Ptr>;

using SSL_X509_PUBKEY_Ptr =
        std::unique_ptr<X509_PUBKEY,
                        SSLDeleter<X509_PUBKEY, lib::OpenSSLLib::SSL_X509_PUBKEY_free>>;
using SSL_X509_PUBKEY_SharedPtr = utility::SharedPtrTypeFromUniquePtr<SSL_X509_PUBKEY_Ptr>;

using SSL_X509_STORE_Ptr =
        std::unique_ptr<X509_STORE, SSLDeleter<X509_STORE, lib::OpenSSLLib::SSL_X509_STORE_free>>;
using SSL_X509_STORE_SharedPtr = utility::SharedPtrTypeFromUniquePtr<SSL_X509_STORE_Ptr>;

using SSL_X509_STORE_CTX_Ptr =
        std::unique_ptr<X509_STORE_CTX,
                        SSLDeleter<X509_STORE_CTX, lib::OpenSSLLib::SSL_X509_STORE_CTX_free>>;
using SSL_X509_STORE_CTX_SharedPtr = utility::SharedPtrTypeFromUniquePtr<SSL_X509_STORE_CTX_Ptr>;

using SSL_STACK_X509_Ptr =
        std::unique_ptr<STACK_OF(X509),
                        SSLDeleter<STACK_OF(X509), lib::OpenSSLLib::SSL_sk_X509_free>>;
using SSL_STACK_X509_SharedPtr = utility::SharedPtrTypeFromUniquePtr<SSL_STACK_X509_Ptr>;

using SSL_ASN1_TIME_Ptr =
        std::unique_ptr<ASN1_TIME, SSLDeleter<ASN1_TIME, lib::OpenSSLLib::SSL_ASN1_TIME_free>>;
using SSL_ASN1_TIME_SharedPtr = utility::SharedPtrTypeFromUniquePtr<SSL_ASN1_TIME_Ptr>;

using SSL_ASN1_INTEGER_Ptr =
        std::unique_ptr<ASN1_INTEGER,
                        SSLDeleter<ASN1_INTEGER, lib::OpenSSLLib::SSL_ASN1_INTEGER_free>>;
using SSL_ASN1_INTEGER_SharedPtr = utility::SharedPtrTypeFromUniquePtr<SSL_ASN1_INTEGER_Ptr>;

using SSL_X509_EXTENSION_Ptr =
        std::unique_ptr<X509_EXTENSION,
                        SSLDeleter<X509_EXTENSION, lib::OpenSSLLib::SSL_X509_EXTENSION_free>>;
using SSL_X509_EXTENSION_SharedPtr = utility::SharedPtrTypeFromUniquePtr<SSL_X509_EXTENSION_Ptr>;

using SSL_BIGNUM_Ptr = std::unique_ptr<BIGNUM, SSLDeleter<BIGNUM, lib::OpenSSLLib::SSL_BN_free>>;
using SSL_BIGNUM_SharedPtr = utility::SharedPtrTypeFromUniquePtr<SSL_BIGNUM_Ptr>;

using SSL_char_Ptr = std::unique_ptr<char, SSLDeleter<void, lib::OpenSSLLib::SSL_OPENSSL_free>>;
using SSL_char_SharedPtr = utility::SharedPtrTypeFromUniquePtr<SSL_char_Ptr>;

using SSL_X509_CRL_Ptr =
        std::unique_ptr<X509_CRL, SSLDeleter<X509_CRL, lib::OpenSSLLib::SSL_X509_CRL_free>>;
using SSL_X509_CRL_SharedPtr = utility::SharedPtrTypeFromUniquePtr<SSL_X509_CRL_Ptr>;

using SSL_STACK_X509_CRL_Ptr =
        std::unique_ptr<STACK_OF(X509_CRL),
                        SSLDeleter<STACK_OF(X509_CRL), lib::OpenSSLLib::SSL_sk_X509_CRL_free>>;
using SSL_STACK_X509_CRL_SharedPtr = utility::SharedPtrTypeFromUniquePtr<SSL_STACK_X509_CRL_Ptr>;

using SSL_ECDSA_SIG_Ptr =
        std::unique_ptr<ECDSA_SIG, SSLDeleter<ECDSA_SIG, lib::OpenSSLLib::SSL_ECDSA_SIG_free>>;
using SSL_ECDSA_SIG_SharedPtr = utility::SharedPtrTypeFromUniquePtr<SSL_ECDSA_SIG_Ptr>;

using time_point = std::chrono::system_clock::time_point;

// Note: ENGINE_free() always returns 1. Therefore, SSLRetDeleter is suitable as it ignores return
// value.
using SSL_ENGINE_Ptr =
        std::unique_ptr<ENGINE, SSLRetDeleter<int, ENGINE, lib::OpenSSLLib::SSL_ENGINE_free>>;
using SSL_ENGINE_SharedPtr = utility::SharedPtrTypeFromUniquePtr<SSL_ENGINE_Ptr>;

/* Below are is the "wrapped" OpenSSL library. By convetion, all functions start with an
 * underscore to visually distinguish them from the methods of the class OpenSSLLib and
 * from the native OpenSSL methods.
 */

/*
 * Retrieve the digest value from ctx and places it in md.
 */
void _EVP_DigestFinal_ex(EVP_MD_CTX *ctx, unsigned char *md, unsigned int *s);

/*
 * Hash cnt bytes of data at d into the digest context ctx.
 */
void _EVP_DigestUpdate(EVP_MD_CTX *ctx, const void *d, size_t cnt);

/*
 * Set up digest context ctx to use a digest type from ENGINE impl.
 */
void _EVP_DigestInit_ex(EVP_MD_CTX *ctx, const EVP_MD *type, ENGINE *impl);

/*
 * Initialize digest context ctx.
 */
void _EVP_MD_CTX_init(EVP_MD_CTX *ctx);

/**
 * Create a new EVP_PKEY instance.
 *
 * @throw OpenSSLException when no object could be created.
 */
SSL_EVP_PKEY_Ptr _EVP_PKEY_new();

/**
 * Create a new X509_REQ instance.
 *
 * @throw OpenSSLException when no object could be created.
 */
SSL_X509_REQ_Ptr _X509_REQ_new();

/**
 * Create an EVP_PKEY_CTX instance for the given key.
 *
 * @throw OpenSSLException when the object could not be created.
 *
 * Note that the OpenSSL call has a second parameter of type ENGINE*, which is optional.
 * The ENGINE parameter is currently unused, which is why this parameter has not been included
 * (thankfully C++ supports overloading which is why it can always be added later).
 */
SSL_EVP_PKEY_CTX_Ptr _EVP_PKEY_CTX_new(EVP_PKEY *pkey);

/**
 * Create an EVP_PKEY_CTX instance for the given ID. The IDs come from OpenSSLs native headers.
 *
 * @throw OpenSSLException when the object could not be created.
 *
 * Note that the OpenSSL call has a second parameter of type ENGINE*, which is optional.
 * The ENGINE parameter is currently unused, which is why we have not included this parameter
 * (thankfully C++ supports overloading which is why we can always add this later).
 */
SSL_EVP_PKEY_CTX_Ptr _EVP_PKEY_CTX_new_id(int id);

/**
 * Generate a keypair.
 *
 * Note: The context must have been initialized for key-generation (@see _EVP_PKEY_keygen_init).
 *
 * @throw OpenSSLException if an error occurs in the underlying OpenSSL function.
 */
SSL_EVP_PKEY_Ptr _EVP_PKEY_keygen(EVP_PKEY_CTX *ctx);

/**
 * Initialize the context for key-generation.
 *
 * @throw OpenSSLException if an error occurs in the underlying OpenSSL function.
 */
void _EVP_PKEY_keygen_init(EVP_PKEY_CTX *ctx);

/**
 * Set the number of bits the RSA key should have.
 *
 * When generating an RSA key with the given context,
 * set the number of bits it should have.
 *
 * @throw OpenSSLException if an error occurs in the underlying OpenSSL function.
 */
void _EVP_PKEY_CTX_set_rsa_keygen_bits(EVP_PKEY_CTX *ctx, int mbits);

/**
 * Initializes the key context so we can set the appropriate parameters for the key generation
 * @param ctx [out] initialized context
 * @throw OpenSSLException if an error occurs in the underlying OpenSSL function.
 */
void _EVP_PKEY_paramgen_init(EVP_PKEY_CTX *ctx);

/**
 * Generates the parameters to be used on the key generation.
 * @param ctx context for parameter generation
 * @return the generated parameters to be used on the key generation
 * @throw OpenSSLException if an error occurs in the underlying OpenSSL function.
 */
SSL_EVP_PKEY_Ptr _EVP_PKEY_paramgen(EVP_PKEY_CTX *ctx);

/**
 * Set the the elliptic curve used to generate the key pair
 *
 * @param ctx [in, out] pkey context created to generate the the key.
 * @param nid [in] Identifier of the curve to be used.
 * @throw OpenSSLException if an error occurs in the underlying OpenSSL function.
 */
void _EVP_PKEY_CTX_set_ec_paramgen_curve_nid(EVP_PKEY_CTX *ctx, int nid);

/**
 * Sets the the elliptic curve parameter encoding when generating
 * EC parameters or an EC key
 *
 * @param ctx [in, out] pkey EC parameter or key context
 * @param param_enc [in] Type of parameter encoding to be used
 * @throw OpenSSLException if an error occurs in the underlying OpenSSL function.
 */
void _EVP_PKEY_CTX_set_ec_param_enc(EVP_PKEY_CTX *ctx, int param_enc);

/**
 * @brief Parses a DER-encoded private key ASN.1 structure (see RFC 5958)
 *
 * @param buf The data to parse
 * @param length  The size of the data
 * @return SSL_PKCS8_PRIV_KEY_INFO_Ptr A pointer to the object containing the data
 */
SSL_PKCS8_PRIV_KEY_INFO_Ptr _SSL_d2i_PKCS8_PRIV_KEY_INFO(const unsigned char *buf, long length);

/**
 * Gets the EC group of a given EC key
 */
const EC_GROUP *_EC_KEY_get0_group(const EC_KEY *key);

/**
 * EC_GROUP_get_degree gets the degree of the field. For Fp fields this will be the number of bits
 * in p. For F2^m fields this will be the value m.
 */
int _EC_GROUP_get_degree(const EC_GROUP *group);

/**
 * Gets the NID of the elliptic curve used to generate the EC key.
 */
int _EC_GROUP_get_curve_name(const EC_GROUP *group);

/**
 * Gets the type of a give PKey oject.
 *
 * @param key to retrieve the type from
 * @return Returns the PKEY type being used
 * @throw OpenSSLException if an error occurs in the underlying OpenSSL function.
 */
int _EVP_PKEY_type(const EVP_PKEY *key);

/**
 * Gets the size in bytes of a pkey object
 * @param pkey key to get size from
 * @return the size of provided key
 * @throw OpenSSLException if an error occurs in the underlying OpenSSL function.
 */
int _EVP_PKEY_size(EVP_PKEY *pkey);

/*
 * Check if two public keys are the same. Please note that this function
 * (according to OpenSSL documentation) ONLY compares the public keys
 * in the EVP_PKEY structure.
 *
 * @return true if the public keys are the same
 * @throw OpenSSLException if there was an error while comparing the keys
 */
bool _EVP_PKEY_cmp(const EVP_PKEY *a, const EVP_PKEY *b);

SSL_X509_NAME_Ptr _X509_NAME_new();

enum class ASN1_NID : int {
    CommonName = NID_commonName,
    CountryName = NID_countryName,
    LocalityName = NID_localityName,
    StateOrProvinceName = NID_stateOrProvinceName,
    OrganizationalUnitName = NID_organizationalUnitName,
    OrganizationName = NID_organizationName,
    Pkcs9EmailAddress = NID_pkcs9_emailAddress,
    SerialNumber = NID_serialNumber,
    GivenName = NID_givenName,
    UserId = NID_userId,
    Title = NID_title,
    Initials = NID_initials,  ///< initials NID enum entry
};

enum class ASN1_Name_Entry_Type : int {
    UTF8String = MBSTRING_UTF8,
    ASCIIString = MBSTRING_ASC,
};

/**
 * This enum contains all the NIDs of supported X509v3 extensions.
 */
enum class X509Extension_NID : int {
    BasicConstraints = NID_basic_constraints,
    KeyUsage = NID_key_usage,
    SubjectKeyIdentifier = NID_subject_key_identifier
};

/**
 * Add an entry to the X509_NAME structure
 * via a specified node-identifier NID (@see ASN1_NID).
 *
 * @param name Pointer to an allocated X509_NAME object.
 * @param nid The node identifier
 * @param type The type of the entry (@see ASN1_Name_Entry_Type)
 * @param bytes The data to be added (interpreted according to 'type')
 *
 * @throw OpenSSLException if an error occurs in the underlying OpenSSL function.
 */
void _X509_NAME_add_entry_by_NID(X509_NAME *name,
                                 ASN1_NID nid,
                                 ASN1_Name_Entry_Type type,
                                 std::vector<unsigned char> &bytes);

/**
 * Set the subject-name for the given X509_REQ object.
 *
 * @throw OpenSSLException if an error occurs in the underlying OpenSSL function.
 */
void _X509_REQ_set_subject_name(X509_REQ *req, X509_NAME *name);

/**
 * Set the public key for the given X509_REQ object.
 *
 * @throw OpenSSLException if an error occurs in the underlying OpenSSL function.
 */
void _X509_REQ_set_pubkey(X509_REQ *req, EVP_PKEY *pkey);

/**
 * Set the X509 version for the given X509_REQ object.
 *
 * @throw OpenSSLException if an error occurs in the underlying OpenSSL function.
 */
void _X509_REQ_set_version(X509_REQ *req, unsigned long version);

/**
 * @result pointer to the internal X509_NAME structure.
 *
 * NOTE this result *MUST NOT BE FREED*.
 */
X509_NAME *_X509_REQ_get_subject_name(const X509_REQ *req);

/**
 * Get the public key for the given X509_REQ object.
 *
 * @throw OpenSSLException if an error occurs in the underlying OpenSSL function.
 */
SSL_EVP_PKEY_Ptr _X509_REQ_get_public_key(X509_REQ *req);

/**
 * Verifies the given X509_REQ object against the given public key.
 *
 * @throw OpenSSLException if the verification fails.
 */
void _X509_REQ_verify(X509_REQ *req, EVP_PKEY *key);

/**
 * Write the X509_REQ to PEM format into the given BIO object.
 *
 * @throw OpenSSLException if an error occurs in the underlying OpenSSL function.
 */
void _PEM_write_bio_X509_REQ(BIO *bio, X509_REQ *req);

/**
 * Write the X509 to PEM format into the given BIO object.
 *
 * @throw OpenSSLException if an error occurs in the underlying OpenSSL function.
 */
void _PEM_write_bio_X509(BIO *bio, X509 *x);

/**
 * Read the X509_REQ in PEM format from the given BIO object.
 *
 * @throw OpenSSLException if an error occurs in the underlying OpenSSL function.
 */
SSL_X509_REQ_Ptr _PEM_read_bio_X509_REQ(BIO *bio);

/**
 *
 * We do not use a unique_ptr here because
 * OpenSSL does not provide a free method
 * for this and also makes no mention of if
 * and how this is to be freed.
 *
 * Presumably this points to static memory.
 */
const BIO_METHOD *_BIO_s_mem();

/**
 * Create a new BIO instance for the given method.
 */
SSL_BIO_Ptr _BIO_new(const BIO_METHOD *method);

/**
 * Create a new file-backed BIO object
 *
 * @throw OpenSSLException if an error occurs. In particular, if the file
 *                         cannot be accessed in the desired mode.
 */
SSL_BIO_Ptr _BIO_new_file(const char *filename, const char *mode);

/**
 * Return value of 0 or -1 are possible without inidicating an error.
 * The exact behavior depends on the type of BIO used (i.e. on its
 * method).
 *
 * @param bio The bio object to be read from.
 * @param buf The vector into which data is placed.
 *
 * @return The number of characters read, or -1. If -1 is returned, the interpretation
 *      depends on the method of the 'bio' (@see _BIO_new()).
 * @throw OpenSSLException if BIO_gets is not supported for the method of 'bio'
 */
int _BIO_gets(BIO *bio, std::vector<char> &buf);

/**
 * Return value of 0 or -1 are possible without inidicating an error.
 * The exact behavior depends on the type of BIO used (i.e. on its
 * method).
 *
 * @param bio The bio object to be read from.
 * @param buf The vector into which data is placed.
 *
 * @return The number of characters read, or -1. If -1 is returned, the interpretation
 *      depends on the method of the 'bio' (@see _BIO_new()).
 * @throw OpenSSLException if BIO_gets is not supported for the method of 'bio'
 */
int _BIO_puts(BIO *bio, std::string buf);

/**
 * Return value of 0 or -1 are possible without indicating an error.
 * The exact behavior depends on the type of BIO used (i.e. on its
 * method).
 *
 * @param bio The bio object to write to.
 * @param data The vector from which the data should be written
 *
 * @return The number of characters read, or -1. If -1 is returned, the interpretation
 *      depends on the method of the 'bio' (@see _BIO_new()).
 * @throw OpenSSLException if BIO_gets is not supported for the method of 'bio'
 */
int _BIO_write(BIO *bio, const std::vector<uint8_t> &data);

/**
 * Tries to read numBytes from the BIO object. It resizes the vector
 * to the desired size and then tries to read the data into it.
 * Return value of 0 or -1 are possible without inidicating an error.
 * The exact behavior depends on the type of BIO used (i.e. on its
 * method).
 *
 * @param bio The bio object to read from
 * @param buf The vector to which the data should be read. It gets resized
 *            to the desired length and is overriden by the data being read.
 * @param numBytes number of bytes that should be read. The output buffer is
 *                 resized by the function so that it can fit the data. If less data is
 *                 read, it is shrunk again.
 *
 * @return The number of characters read, or -1. If -1 is returned, the interpretation
 *      depends on the method of the 'bio' (@see _BIO_new()).
 * @throw OpenSSLException if BIO_gets is not supported for the method of 'bio'
 */
int _BIO_read(BIO *bio, std::vector<uint8_t> &buf, std::size_t numBytes);

/*
 * Read a DER encoded X509 certificate from a bio
 *
 * @throw OpenSSLException if an OpenSSL internal error occurs.
 */
SSL_X509_Ptr _d2i_X509_bio(BIO *bp);

/*
 * Read a DER encoded X509 certificate request from a bio
 *
 * @throw OpenSSLException if an OpenSSL internal error occurs.
 */
SSL_X509_REQ_Ptr _d2i_X509_REQ_bio(BIO *bp);

/*
 * Write an X509 certificate in DER encoded form to a bio
 *
 * @throw OpenSSLException if an OpenSSL internal error occurs.
 */
void _i2d_X509_bio(BIO *bp, X509 *x);

/*
 * Write an X509 certification request in DER encoded form to a bio
 *
 * @throw OpenSSLException if an OpenSSL internal error occurs.
 */
void _i2d_X509_REQ_bio(BIO *bp, X509_REQ *x);

/**
 * Sign an X509_REQ to obtain a complete CSR.
 *
 * @throw OpenSSLException if an error occurs in the underlying OpenSSL function.
 */
void _X509_REQ_sign_ctx(X509_REQ *req, EVP_MD_CTX *ctx);

/**
 * Get reference to digest function for a given digest type.
 *
 * @throws std::runtime_error if the requested digest function was not found.
 */
const EVP_MD *_getMDPtrFromDigestType(DigestTypes type);

/**
 * Get OSSL Params array for a given digest type.
 * @param type
 * @throws std::runtime_error if the requested digest function was not found.
 */
const std::array<OSSL_PARAM, 4> _getOSSLParamFromDigestType(DigestTypes type);

/**
 * Create an MD_CTX object.
 *
 * @throw OpenSSLException if an error occurs in the underlying OpenSSL function.
 */
SSL_EVP_MD_CTX_Ptr _EVP_MD_CTX_create();

/**
 *
 * Write the given private key to the given bio.
 *
 * Encrypts the given private key (encrypted PEM).
 *
 * Note: The password is intentionally passed by value because openssl does not guarantee the
 * underlying C-string to be unmodified. To avoid nasty surprises, we copy the string so OpenSSL
 * can mess with it if needed.
 *
 * @param pwd Password to be used to encrypt the key.
 * @param cipher The cipher to be used for the encryption (may be nullptr, then no encryption
 *      occurs).
 * @param out The bio to write to.
 * @param pkey The public key structure that holds the private key.
 *
 * @throws OpenSSLException if an error occurs in the underlying OpenSSL function.
 *
 */
void _PEM_write_bio_PKCS8PrivateKey(BIO *out,
                                    EVP_PKEY *pkey,
                                    const EVP_CIPHER *cipher,
                                    std::string pwd);
void _PEM_write_bio_PUBKEY(BIO *bp, EVP_PKEY *x);

/**
 * Note: The password is intentionally passed by value because openssl does not guarantee the
 * underlying C-string to be unmodified. To avoid nasty surprises, we copy the string so OpenSSL
 * can mess with it if needed.
 *
 * NOTE: The corresponding "write: method refers to PKCS8, but the read method
 * multiplexes based on the format of the data in "pwd". Hence, OpenSSL does
 * not provide a '..._read_bio_PKCS8PrivateKey' function.
 *
 * @param bio The BIO instance to read the key from.
 * @param pwd The password (as ASCII string) to decrypt the key with.
 */
SSL_EVP_PKEY_Ptr _PEM_read_bio_PrivateKey(BIO *bio, std::string pwd);

/**
 * @param bio The BIO instance to read the key from.
 */
SSL_EVP_PKEY_Ptr _PEM_read_bio_PUBKEY(BIO *bio);

/**
 * Read an X509 certificate from BIO instance.
 *
 * @param bio a pointer to a bio instance.
 *
 * @throws OpenSSLException if an internal OpenSSL error is encountered.
 *
 */
SSL_X509_Ptr _PEM_read_bio_X509(BIO *bio);

/**
 * Let OpenSSL compute the time difference between two ASN1_TIMEs
 *
 * @param pday A pointer to which the full days difference is stored
 * @param psec A pointer to which the seconds difference is stored
 * @param from The first date
 * @param to The second date. If to is earlier than from, pday or
 *           psec will be written with a negative value (or 0).
 * @throw OpenSSLException when an error occurs (e.g., wrong ASN1_TIME formats)
 */
void _ASN1_TIME_diff(int *pday, int *psec, const ASN1_TIME *from, const ASN1_TIME *to);

/**
 * Get an ASN1_TIME object from a time_t
 *
 * @throw OpenSSLException if an error occurs creating the object
 */
SSL_ASN1_TIME_Ptr _ASN1_TIME_from_time_t(time_t t);

/**
 * Set the time from a textual representation to an ASN.1 time
 */
void _ASN1_TIME_set_string(ASN1_TIME *s, const char *str);

/**
 * Add an X509 certificate to an X509 store
 *
 * @param store The X509 store to add to
 * @param cert The X509 certificate to be added
 *
 * @throw OpenSSLException when an error occurs while adding the certificate
 */
void _X509_STORE_add_cert(X509_STORE *store, X509 *cert);

/**
 * Initialize an X509 store context
 *
 * @param ctx The context to be initialized
 * @param store
 * @param x509
 * @param chain
 *
 * @throw OpenSSLException when an error occurs while initializing
 *                         the context
 */
void _X509_STORE_CTX_init(X509_STORE_CTX *ctx,
                          X509_STORE *store,
                          X509 *x509,
                          STACK_OF(X509) * chain);

/**
 * Get the verification parameters for an X509 store context
 *
 * @param ctx The context
 *
 * @throw OpenSSLException if an error occurs
 */
X509_VERIFY_PARAM *_X509_STORE_CTX_get0_param(X509_STORE_CTX *ctx);

/**
 * @brief Verify if the certificate is a CA
 *
 * @return Whether the certificate is a CA or not
 */
bool _X509_check_ca(X509 *cert);

class X509VerificationFlags
{
public:
    static constexpr unsigned long PARTIAL_CHAIN = X509_V_FLAG_PARTIAL_CHAIN;
    static constexpr unsigned long CRL_CHECK_ALL = X509_V_FLAG_CRL_CHECK_ALL;
    static constexpr unsigned long CRL_CHECK = X509_V_FLAG_CRL_CHECK;
    static constexpr unsigned long USE_CHECK_TIME = X509_V_FLAG_USE_CHECK_TIME;
};

/**
 * Set X509 verification flags
 *
 * @param param The X509 verifcation parameters object
 * @param flags New flags
 *
 * @throw OpenSSLException if an error occurs
 */
void _X509_VERIFY_PARAM_set_flags(X509_VERIFY_PARAM *param, unsigned long flags);

/**
 * Verify an X509 certificate with the given certification context.
 *
 * @param ctx The context to verify
 *
 * @throw OpenSSLException if the verification failed.
 */
void _X509_verify_cert(X509_STORE_CTX *ctx);

/**
 * Wrapper to create openssl objects
 *
 * Create an instance of the openssl object type provided in the template
 * parameter.
 *
 * @throw OpenSSLException when no object could be created
 */
template <class SslType>
SslType *createOpenSSLObject();

template <class SSLSmartPtrType>
SSLSmartPtrType createManagedOpenSSLObject()
{
    return SSLSmartPtrType{createOpenSSLObject<typename SSLSmartPtrType::element_type>()};
}

template <class StackType, class ObjType>
void addObjectToStack(StackType *stack, const ObjType *obj);

/**
 * @result pointer to the internal X509_NAME structure.
 *
 * NOTE this result *MUST NOT BE FREED*.
 */
X509_NAME *_X509_get_subject_name(X509 *obj);

/**
 * @result pointer to the internal X509_NAME structure.
 *
 * NOTE this result *MUST NOT BE FREED*.
 */
X509_NAME *_X509_get_issuer_name(X509 *obj);

/**
 * Get not before value of the certificate as system_clock::time_point
 *
 * @throw OpenSSLException if an internal OpenSSL error is encountered
 */
time_point _X509_get_notBefore(X509 *x);

/**
 * Get not after value of the certificate as system_clock::time_point
 *
 * @throw OpenSSLException if an internal OpenSSL error is encountered
 */
time_point _X509_get_notAfter(X509 *x);

/**
 * Get not before value of the certificate as ASN1_TIME
 *
 * @throw OpenSSLException if an internal OpenSSL error is encountered
 */
ASN1_TIME *_X509_get_notBefore_ASN1(X509 *x);

/**
 * Get not after value of the certificate as ASN1_TIME
 *
 * @throw OpenSSLException if an internal OpenSSL error is encountered
 */
ASN1_TIME *_X509_get_notAfter_ASN1(X509 *x);

/**
 * Get a pointer to the EVP_PKEY in a certificate.
 *
 * Using this call increments the OpenSSL internal reference count of
 * the public key. Hence, you get a memory managed object as return value
 * of this function. However, the object will only be freed once the
 * OpenSSL internal reference count reaches 0.
 *
 * @throw OpenSSLException if there is an error in retrieving the key
 */
SSL_EVP_PKEY_Ptr _X509_get_pubkey(X509 *x);

/**
 * Set the subject-name for the given X509 object.
 *
 * @throw OpenSSLException if an error occurs in the underlying OpenSSL function.
 */
void _X509_set_subject_name(X509 *x, X509_NAME *name);

/**
 * Set the issuer-name for the given X509 object.
 *
 * @throw OpenSSLException if an error occurs in the underlying OpenSSL function.
 */
void _X509_set_issuer_name(X509 *x, X509_NAME *name);

/**
 * Set the public key for the given X509 object.
 *
 * @throw OpenSSLException if an error occurs in the underlying OpenSSL function.
 */
void _X509_set_pubkey(X509 *x, EVP_PKEY *key);

/**
 * Set not before value of the certificate as system_clock::time_point
 *
 * @throw OpenSSLException if an internal OpenSSL error is encountered
 */
void _X509_set_notBefore(X509 *x, const time_point &t);

/**
 * Set not after value of the certificate as system_clock::time_point
 *
 * @throw OpenSSLException if an internal OpenSSL error is encountered
 */
void _X509_set_notAfter(X509 *x, const time_point &t);

/**
 * Set not before value of the certificate as ASN1_TIME
 *
 * @throw OpenSSLException if an internal OpenSSL error is encountered
 */
void _X509_set_notBefore_ASN1(X509 *x, const ASN1_TIME *t);

/**
 * Set not after value of the certificate as ASN1_TIME
 *
 * @throw OpenSSLException if an internal OpenSSL error is encountered
 */
void _X509_set_notAfter_ASN1(X509 *x, const ASN1_TIME *t);

/**
 * Creates a new X509 certificate.
 *
 * @throw OpenSSLException if an internal OpenSSL error is encountered
 */
SSL_X509_Ptr _X509_new();

void _X509_sign(X509 *x, EVP_PKEY *pkey, DigestTypes type);

/**
 * Return the list of locations in the structure that contain an entry with
 * the given NID.
 *
 * @param name The X509_NAME structure
 * @param nid  The ASN1_NID
 *
 * @return A vector of positions of 'nid'. Empty, if 'nid' could not be found in 'name'
 *
 * @throws OpenSSLException if an internal OpenSSL error is encoutered.
 */
std::vector<int> _X509_NAME_get_index_by_NID(X509_NAME *name, ASN1_NID nid);

/**
 * Retrieve the entry at the given position.
 *
 * The position 'loc' must first be obtained via _X509_NAME_get_index_by_NID.
 *
 * @param name The structure from which to retrieve the entry
 * @param loc  The position at which to search (@see _X509_NAME_get_index_by_NID).
 * @result pointer to the internal X509_NAME_ENTRY structure.
 *
 * NOTE: this result *MUST NOT BE FREED*.
 *
 * @throws OpenSSLException if an internal OpenSSL error is encoutered.
 *
 */
X509_NAME_ENTRY *_X509_NAME_get_entry(X509_NAME *name, int loc);

std::string _X509_NAME_ENTRY_get_data(X509_NAME_ENTRY *entry);

/**
 * Return name of given cipher
 *
 * @param cipher to get the name for
 * @returns name of cipher
 */
const std::string _EVP_CIPHER_name(const EVP_CIPHER *cipher);

/**
 * Return size of key used for given cipher
 *
 * @param cipher to get the key size for
 * @returns size of key in bytes
 */
int _EVP_CIPHER_key_length(const EVP_CIPHER *cipher);

using SSL_EVP_CIPHER_CTX_Ptr =
        std::unique_ptr<EVP_CIPHER_CTX,
                        SSLDeleter<EVP_CIPHER_CTX, lib::OpenSSLLib::SSL_EVP_CIPHER_CTX_free>>;
using SSL_EVP_CIPHER_CTX_SharedPtr = utility::SharedPtrTypeFromUniquePtr<SSL_EVP_CIPHER_CTX_Ptr>;

/**
 * Create new cipher context.
 * @sa _EVP_CIPHER_CTX_ctrl()
 */
SSL_EVP_CIPHER_CTX_Ptr _EVP_CIPHER_CTX_new();

/**
 * Clears all information from a cipher context and free up any allocated memory associated with it,
 * except the ctx itself.
 */
void _EVP_CIPHER_CTX_reset(EVP_CIPHER_CTX *ctx);

/**
 * Allows various cipher specific parameters to be determined and set
 */
void _EVP_CIPHER_CTX_ctrl(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr);

/**
 * Sets up cipher context `ctx` for encryption or decryption.
 *
 * @param ctx cipher context to set
 * @param cipher cipher implementation e.g. `EVP_aes_256_cbc()`
 * @param impl  If impl is NULL then the default implementation is used.
 * @param key the symmetric key to use
 * @param iv the IV to use (if necessary),
 * @param enc 1 if context should be initialized for encryption and 0 if fo decryption.
 */
void _EVP_CipherInit_ex(EVP_CIPHER_CTX *ctx,
                        const EVP_CIPHER *cipher,
                        ENGINE *impl,
                        const unsigned char *key,
                        const unsigned char *iv,
                        int enc);

/**
 * Can be used for encryption or decryption depending on how cipher context was initialized.
 *
 * This function wraps `EVP_EncryptUpdate()` and `EVP_DecryptUpdate()` of OpenSSL. Please reference
 * OpenSSL man pages for more details.
 *
 * @sa _EVP_CipherInit_ex
 *
 * @param ctx cipher context
 * @param outm output buffer
 * @param outl length of the output buffer. At the input the function expects size of the \c outm
 * to be placed in \c outl. At the output, the actual amount of data written to \c outm will be
 * stored in this variable. The amount of data written depends on the block alignment
 *  of the encrypted/decrypted data.
 * @param in input buffer
 * @param inl length of the input buffer.
 */
void _EVP_CipherUpdate(
        EVP_CIPHER_CTX *ctx, unsigned char *outm, int *outl, const unsigned char *in, int inl);

/**
 * If padding is enabled (the default) this function encrypts/decrypts the "final" data, that is
 * any data that remains in a partial block. Please take a look at the OpenSSL
 * `EVP_EncryptFinal_ex()` and `EVP_DecryptFinal_ex()` documentation for more details.
 *
 * @note After this function is called the encryption/decryption operation is finished and no
 * further calls to _EVP_CipherUpdate() should be made.
 *
 * @param ctx cipher context
 * @param outm output buffer
 * @param outl At the input the function expects size of the \c outm to be placed in \c outl.
 * At the output, the actual amount of data written to \c outm will be stored in this variable.
 */
void _EVP_CipherFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *outm, int *outl);

/**
 * Get the key length of a cipher.
 * @param ctx cipher context
 * @return key length of a cipher in bytes.
 */
int _EVP_CIPHER_CTX_key_length(const EVP_CIPHER_CTX *ctx);

/**
 * Get the IV length of a cipher.
 *
 * It will return zero if the cipher does not use an IV
 *
 * @param ctx cipher context
 * @return IV length of a cipher in bytes.
 */
int _EVP_CIPHER_CTX_iv_length(const EVP_CIPHER_CTX *ctx);

/**
 * Enables or disables padding.
 *
 * This function should be called after the context is set up for encryption or decryption with
 * `_EVP_EncryptInit_ex()`.  If the pad parameter is zero then no padding is performed, the total
 * amount of data encrypted or decrypted must then be a multiple of the block size or an error will
 * occur.
 */

void _EVP_CIPHER_CTX_set_padding(EVP_CIPHER_CTX *ctx, int pad);

/**
 * Get the cipher descriptor for AES 256 in CBC mode.
 * The result should not be freed (at least it is const and openssl apps don't do it)
 *
 * @result A const pointer to the respective EVP_CIPHER struct
 * @throws OpenSSLException if an internal OpenSSL error is encountered
 */
const EVP_CIPHER *_EVP_aes_256_cbc();

/**
 * Creates a new X509 extension, identified by its NID, from its string representation.
 *
 * @param ext_nid the NID for the extension that should be created
 * @param ctx the context for the extension that should be created
 * @param value the value of the extension that should be created
 * @return a unique pointer to the created extension
 */
SSL_X509_EXTENSION_Ptr _X509V3_EXT_conf_nid(int ext_nid, X509V3_CTX *ctx, std::string value);

/**
 * Sets that there is no configuration database for a context.
 * @param ctx the context which is set
 */
void _X509V3_set_ctx_nodb(X509V3_CTX *ctx);

/**
 * Sets the information within a context.
 * @param ctx the context which is set.
 * @param issuer the issuing certificate for this context
 * @param subject the subject certificate for this context
 */
void _X509V3_set_ctx(X509V3_CTX *ctx, X509 *issuer, X509 *subject);

/**
 * Adds an X509 extension to an X509 certificate.
 *
 * @param x the certificate
 * @param ex the new extension
 */
void _X509_add_ext(X509 *x, X509_EXTENSION *ex);

/**
 * Sets the serial number of a certificate.
 * @param x the certificate
 * @param serial the new serial number
 */
void _X509_set_serialNumber(X509 *x, uint64_t serial);

/**
 * Gets the serial number of a certificate.
 * @param x the certificate
 * @return the serial number of the passed certificate
 */
uint64_t _X509_get_serialNumber(X509 *x);

/**
 * Gets the serial number of a certificate with arbitrary precision as a decimal representation in
 * ASCII.
 *
 * @param x the certificate
 * @return the decimal string representation of the serial number
 */
std::string _X509_get_serialNumber_dec(X509 *x);

/**
 * Gets the serial number of a certificate with arbitrary precision as a binary representation.
 *
 * @param x the certificate
 * @return the binary representation of the serial number
 */
std::vector<uint8_t> _X509_get_serialNumber_bin(X509 *x);

/**
 * Creates a new (empty) ASN1_TIME object.
 *
 * Unfortunately, openssl ASN1 objects are borked and many are just typedefs for ASN1_STRING.
 * Hence, we cannot use the template function to create them but need to create separate function.
 */
SSL_ASN1_TIME_Ptr _ASN1_TIME_new();

/**
 * Create a copy of a raw openssl ASN1_TIME objec
 */
SSL_ASN1_TIME_Ptr _ASN1_TIME_copy(const ASN1_TIME *t);

/**
 * Convert an ASN1_TIME object to a C++ time_point
 */
time_point _asn1TimeToTimePoint(const ASN1_TIME *time);

/**
 * Gets the time for the next, planned update for a CRL.
 */
const ASN1_TIME *_X509_CRL_get_nextUpdate(const X509_CRL *crl);

/**
 * Gets the time for the creation of a CRL.
 */
const ASN1_TIME *_X509_CRL_get_lastUpdate(const X509_CRL *crl);

/**
 * Verifies the signature of a crl with a given public key.
 */
void _X509_CRL_verify(X509_CRL *crl, EVP_PKEY *key);

/**
 * Gets the issuer (the issuer name of the CA certificate) of a CRL.
 */
X509_NAME *_X509_CRL_get_issuer(const X509_CRL *crl);

/**
 * Writes a CRL as PEM encoded to a BIO object.
 */
void _PEM_write_bio_X509_CRL(BIO *bio, X509_CRL *crl);

/**
 * Reads a PEM encoded CRL from a BIO object.
 */
SSL_X509_CRL_Ptr _PEM_read_bio_X509_CRL(BIO *bp);

/**
 * Reads a DER encoded CRL from a BIO object.
 */
SSL_X509_CRL_Ptr _d2i_X509_CRL_bio(BIO *bp);

/**
 * Reads a DER encoded x509 pubkey from a buffer.
 */
SSL_X509_PUBKEY_Ptr _d2i_X509_PUBKEY(const unsigned char *pin, long length);

/**
 * Sets a list of CRLs for a verification context.
 */
void _X509_STORE_CTX_set0_crls(X509_STORE_CTX *ctx, STACK_OF(X509_CRL) * crls);

/**
 * Adds a specific amount of days and seconds to a time_t and returns it as an ASN1_TIME.
 */
SSL_ASN1_TIME_Ptr _ASN1_TIME_adj(std::time_t t, int days, long seconds);

/**
 * Prints an ASN1_STRING to a BIO object.
 */
void _ASN1_STRING_print_ex(BIO *out, const ASN1_STRING *str);

/**
 * Sets the time of verification for a verification context.
 */
void _X509_STORE_CTX_set_time(X509_STORE_CTX *ctx, std::time_t time);

/**
 * Converts an ASN1_TIME to a time_t.
 * @throw OpenSSLException if the ASN1_TIME doesn't fit into a time_t.
 */
time_t _asn1TimeToTimeT(const ASN1_TIME *time);

/**
 * @brief Returns the int64_t from an ASN1_INTEGER
 *
 * @param a the ASN1_INTEGER variable
 * @return int64_t the stored value
 */
int64_t _SSL_ASN1_INTEGER_get_int64(const ASN1_INTEGER *a);

enum class RSAPaddingMode {
    NONE = RSA_NO_PADDING,
    PKCS1 = RSA_PKCS1_PADDING,
    PSS = RSA_PKCS1_PSS_PADDING,
    OAEP = RSA_PKCS1_OAEP_PADDING
};

/**
 * Signs a message
 */
void _EVP_PKEY_sign(EVP_PKEY_CTX *ctx,
                    unsigned char *sig,
                    size_t *siglen,
                    const unsigned char *tbs,
                    size_t tbslen);

/**
 * Initializes the context for a signature
 */
void _EVP_PKEY_sign_init(EVP_PKEY_CTX *ctx);

/**
 * Initializes the context for a RSA signature verification
 */
void _EVP_PKEY_verify_init(EVP_PKEY_CTX *ctx);

/**
 * Performs a RSA signature verification
 */
void _EVP_PKEY_verify(EVP_PKEY_CTX *ctx,
                      const unsigned char *sig,
                      size_t siglen,
                      const unsigned char *tbs,
                      size_t tbslen);

/**
 * Initialize the MD_CTX for signing, using a given digest-type and a given
 * public key.
 *
 * @param ctx The context to be set up for signing.
 * @param md The digest type (@see DigestTypes)
 * @param pkey The public key to be used.
 *
 * @throw OpenSSLException if an error occurs in the underlying OpenSSL function.
 */
void _EVP_DigestSignInit(EVP_MD_CTX *ctx, DigestTypes md, EVP_PKEY *pkey);

/**
 * Perform a digital signature of the message and store the signature in signatureBuffer.
 *
 * @param ctx The context used for signing.
 * @param signatureBuffer The buffer to write the signature to.
 * @param signatureBufferLength The length of the generated signature.
 * @param message Message to be signed.
 * @param messageLength Length of the message to be signed.
 *
 * @throw OpenSSLException if an error occurs in the underlying OpenSSL function.
 */
void _EVP_DigestSign(EVP_MD_CTX *ctx,
                     unsigned char *signatureBuffer,
                     size_t *signatureBufferLength,
                     const unsigned char *message,
                     size_t messageLength);

/**
 * Initialize the MD_CTX for verification, using a given digest-type and a given
 * public key.
 *
 * @param ctx The context to be set up for verification.
 * @param type The digest type (@see DigestTypes)
 * @param pkey The public key to be used.
 *
 * @throw OpenSSLException if an error occurs in the underlying OpenSSL function.
 */
void _EVP_DigestVerifyInit(EVP_MD_CTX *ctx, DigestTypes type, EVP_PKEY *pkey);

/**
 * Verifies a given digital signature of the given message.
 *
 * @param ctx The context used for verification.
 * @param signature The signature to be verified.
 * @param signatureLength The length of the the signature to be verified.
 * @param message Signed message.
 * @param messageLength Length of the signed message.
 *
 * @throw OpenSSLException if an error occurs in the underlying OpenSSL function.
 */
void _EVP_DigestVerify(EVP_MD_CTX *ctx,
                       const unsigned char *signature,
                       size_t signatureLength,
                       const unsigned char *message,
                       size_t messageLength);
/**
 * Sets the RSA padding
 */
void _EVP_PKEY_CTX_set_rsa_padding(EVP_PKEY_CTX *ctx, int pad);

/**
 * Sets the masking algorithm
 */
void _EVP_PKEY_CTX_set_signature_md(EVP_PKEY_CTX *ctx, const EVP_MD *md);
/**
 * Sets the salt length
 */
void _EVP_PKEY_CTX_set_rsa_pss_saltlen(EVP_PKEY_CTX *ctx, int len);
/**
 * Sets the mgf1
 */
void _EVP_PKEY_CTX_set_rsa_mgf1_md(EVP_PKEY_CTX *ctx, const EVP_MD *md);

/**
 * Initializes the context for an encryption operation
 */
void _EVP_PKEY_encrypt_init(EVP_PKEY_CTX *ctx);

/**
 * Encrypts a message
 */
void _EVP_PKEY_encrypt(EVP_PKEY_CTX *ctx,
                       unsigned char *out,
                       size_t *outlen,
                       const unsigned char *in,
                       size_t inlen);

/**
 * Initializes the context for an decryption operation
 */
void _EVP_PKEY_decrypt_init(EVP_PKEY_CTX *ctx);

/**
 * Decrypts a message
 */
void _EVP_PKEY_decrypt(EVP_PKEY_CTX *ctx,
                       unsigned char *out,
                       size_t *outlen,
                       const unsigned char *in,
                       size_t inlen);

/**
 * Sets the OAEP hashing function
 */
void _EVP_PKEY_CTX_set_rsa_oaep_md(EVP_PKEY_CTX *ctx, const EVP_MD *md);

/**
 * Sets the OAEP label
 */
void _EVP_PKEY_CTX_set_rsa_oaep_label(EVP_PKEY_CTX *ctx, unsigned char *l, int llen);

/**
 * Returns the size of an RSA Key
 */
int _RSA_size(const RSA *r);

/**
 * Returns the size of a message digest
 */
int _EVP_MD_size(const EVP_MD *md);

/**
 * Allocates memory
 */
void *_OPENSSL_malloc(int num);

/**
 * Generate random data.
 *
 * RAND_bytes() puts num cryptographically strong pseudo-random bytes into buf.
 */
void _RAND_bytes(unsigned char *buf, int num);

void _CRYPTO_malloc_init();

enum class ellipticCurveNid {
    PRIME_192v1 = NID_X9_62_prime192v1,
    PRIME_256v1 = NID_X9_62_prime256v1,

    SECP_224r1 = NID_secp224r1,
    SECP_384r1 = NID_secp384r1,
    SECP_521r1 = NID_secp521r1,

    SECT_283k1 = NID_sect283k1,
    SECT_283r1 = NID_sect283r1,
    SECT_409k1 = NID_sect409k1,
    SECT_409r1 = NID_sect409r1,
    SECT_571k1 = NID_sect571k1,
    SECT_571r1 = NID_sect571r1,

    Ed448 = NID_ED448,
    Ed25519 = NID_ED25519
};

enum class EllipticCurvePointConversionForm {
    /* the point is encoded as z||x, where the octet z specifies
     * which solution of the quadratic equation y is  */
    compressed = POINT_CONVERSION_COMPRESSED,
    /* the point is encoded as z||x||y, where z is the octet 0x04  */
    uncompressed = POINT_CONVERSION_UNCOMPRESSED,
    /* the point is encoded as z||x||y, where the octet z specifies
     * which solution of the quadratic equation y is  */
    hybrid = POINT_CONVERSION_HYBRID

};

const EC_KEY *_EVP_PKEY_get0_EC_KEY(EVP_PKEY *pkey);

void _PKCS5_PBKDF2_HMAC(const std::vector<uint8_t> pass,
                        const std::vector<uint8_t> salt,
                        int iter,
                        const EVP_MD *digest,
                        std::vector<uint8_t> &out);

void _ECDH_KDF_X9_63(std::vector<uint8_t> &out,
                     const std::vector<uint8_t> &Z,
                     const std::vector<uint8_t> &sinfo,
                     const EVP_MD *md);

OSSL_LIB_CTX_Ptr _OSSL_LIB_CTX_new(void);

/* HMAC */
void _EVP_MAC_init(EVP_MAC_CTX *ctx, const std::vector<uint8_t> &key, const OSSL_PARAM params[]);
std::vector<uint8_t> _EVP_MAC_final(EVP_MAC_CTX *ctx);
void _EVP_MAC_update(EVP_MAC_CTX *ctx, const std::vector<uint8_t> &data);
EVP_MAC_CTX_Ptr _EVP_MAC_CTX_new(EVP_MAC_Ptr mac);

EVP_MAC_Ptr _EVP_MAC_fetch(OSSL_LIB_CTX *libctx, std::string algorithm);

/* CMAC */
SSL_CMAC_CTX_Ptr _CMAC_CTX_new(void);
void _CMAC_Init(CMAC_CTX *ctx,
                const std::vector<uint8_t> &key,
                const EVP_CIPHER *cipher,
                ENGINE *impl);
void _CMAC_Update(CMAC_CTX *ctx, const std::vector<uint8_t> &data);
std::vector<uint8_t> _CMAC_Final(CMAC_CTX *ctx);
const EVP_CIPHER *_getCipherPtrFromCmacCipherType(CmacCipherTypes cipherType);

SSL_EC_KEY_Ptr _EC_KEY_oct2key(int nid, const std::vector<uint8_t> &buf);
void _EVP_PKEY_set1_EC_KEY(EVP_PKEY *pkey, EC_KEY *key);

std::vector<uint8_t> _EC_KEY_key2buf(const EVP_PKEY *evp, point_conversion_form_t form);
/**
 * @brief _EVP_derive_key calculates a new public key P_new
 *
 * For EC: The returned value is the x-coordinate of the EC-Point (not sure for curve448 and 25519).
 *         The EC-Point is the result of the calculation (P_new = key * peerkey)
 *
 * Never use a derived secret directly. Typically it is passed through some hash function to produce
 * a key
 * @param peerkey The public key
 * @param key The private key
 * @return The new public key
 */
std::vector<uint8_t> _EVP_derive_key(const EVP_PKEY *peerkey, const EVP_PKEY *key);

/* ECDSA Special */
/**
 * Set the r and s signature components from r and s a bignums
 */
void _ECDSA_SIG_set0(ECDSA_SIG *sig, SSL_BIGNUM_Ptr r, SSL_BIGNUM_Ptr s);

/**
 * Get the r signature component as bignum
 */
const BIGNUM *_ECDSA_SIG_get0_r(const ECDSA_SIG *sig);

/**
 * Get the s signature component as bignum
 */
const BIGNUM *_ECDSA_SIG_get0_s(const ECDSA_SIG *sig);

/**
 * Get the serialized ECDSA signature in ASN.1 format from ECDSA_SIG object
 */
std::vector<uint8_t> _i2d_ECDSA_SIG(const ECDSA_SIG *);

/**
 * Create ECDSA_SIG object from serialized ECDSA signature.
 */
SSL_ECDSA_SIG_Ptr _d2i_ECDSA_SIG(const std::vector<uint8_t> &signature);

/* Bignum related */

/**
 * Generate an OpenSSL bignum from the big-endian plain bytes representation
 * of an unsigned integer.
 *
 * @return A smart pointer to the bignum object
 * @throw OpenSSLException is a problem occurs during the conversion
 */
SSL_BIGNUM_Ptr _BN_bin2bn(const uint8_t *data, size_t dataLen);

/**
 * Write an OpenSSL bignum in big-endian plain bytes representation of an
 * unsigned integer. Returned vector will be padded if necessary.
 *
 * @param bignum Number to serialize
 * @param tolen Length of the vector that will be returned
 * @return Vector containing serialized number
 * @throw OpenSSLException if tolen bytes cannot hold bignum
 */
std::vector<uint8_t> _BN_bn2binpad(const BIGNUM *bignum, int tolen);

/* Engine related */

/**
 * Loads an engine based on the passed ID \p engineId.
 */
SSL_ENGINE_Ptr _ENGINE_by_id(const std::string &engineId);

/**
 * Initialises engine \p e.
 */
void _ENGINE_init(ENGINE *e);

/**
 * Issues a command \p cmdName to the engine \p e. Takes a string \p cmdArg as input data.
 */
void _ENGINE_ctrl_cmd_string(ENGINE *e, const std::string &cmdName, const std::string &cmdArg);

/**
 * Load private key via Engine \p e. Mainly used with HSMs which are modelled as
 * OpenSSL engines.
 *
 * @param e The engine for loading the private key.
 * @param keyId The ID of the key.
 */
SSL_EVP_PKEY_Ptr _ENGINE_load_private_key(ENGINE *e, const std::string &keyId);

/**
 * Load private key via Engine \p e. Mainly used with HSMs which are modelled as
 * OpenSSL engines.
 *
 * @param e The engine for loading the private key.
 * @param keyId The ID of the key.
 */
SSL_EVP_PKEY_Ptr _ENGINE_load_public_key(ENGINE *e, const std::string &keyId);

/**
 * Clear engine's functional reference.
 */
void _ENGINE_finish(ENGINE *e);

/**
 * Send control command to an engine and pass arbitrary data through \p p
 */
void _ENGINE_ctrl_cmd(ENGINE *e, const std::string &cmdName, void *p);

/**
 * Convert integer \p nid to curve name
 */
std::string _EC_curve_nid2nist(int nid);

/**
 * Get number of bits key has from \p pkey data structure
 */
int _EVP_PKEY_bits(EVP_PKEY *pkey);

/**
 * Overwrite sensitive memory chunk
 */
void _OPENSSL_cleanse(void *ptr, size_t size);

}  // namespace openssl
}  // namespace mococrw
