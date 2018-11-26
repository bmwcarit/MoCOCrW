/*
 * #%L
 * %%
 * Copyright (C) 2018 BMW Car IT GmbH
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

#include <ctime>
#include <chrono>
#include <memory>
#include <vector>
#include "boost/format.hpp"

#include "openssl_lib.h"
#include "util.h"

namespace mococrw
{
namespace openssl
{
/**
 * Template to wrap OpenSSLs "_free" functions
 * into a functor so that a std::unique_ptr
 * can use them.
 */
template <class P, void(Func)(P*)>
struct SSLDeleter
{
    template<class T>
    void operator()(T* ptr) const noexcept
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
  void operator()(P* ptr)
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
    explicit OpenSSLException(StringType&& message)
            : _message{std::forward<StringType>(message)}
    {
    }

    /**
     * Generate an exception with the defalt OpenSSL error-string
     * as message.
     *
     */
    OpenSSLException() : _message{generateOpenSSLErrorString()} {}

    const char* what() const noexcept override { return _message.c_str(); }
private:
    static std::string generateOpenSSLErrorString();
    std::string _message;
};

/*
 * Wrap all the pointer-types returned by openssl.
 */
using SSL_EVP_PKEY_Ptr =
        std::unique_ptr<EVP_PKEY, SSLDeleter<EVP_PKEY, lib::OpenSSLLib::SSL_EVP_PKEY_free>>;
using SSL_EVP_PKEY_SharedPtr = utility::SharedPtrTypeFromUniquePtr<SSL_EVP_PKEY_Ptr>;

using SSL_EVP_PKEY_CTX_Ptr =
        std::unique_ptr<EVP_PKEY_CTX,
                        SSLDeleter<EVP_PKEY_CTX, lib::OpenSSLLib::SSL_EVP_PKEY_CTX_free>>;
using SSL_EVP_PKEY_CTX_SharedPtr = utility::SharedPtrTypeFromUniquePtr<SSL_EVP_PKEY_CTX_Ptr>;

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

using SSL_X509_Ptr =
        std::unique_ptr<X509, SSLDeleter<X509, lib::OpenSSLLib::SSL_X509_free>>;
using SSL_X509_SharedPtr = utility::SharedPtrTypeFromUniquePtr<SSL_X509_Ptr>;

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
        std::unique_ptr<ASN1_INTEGER, SSLDeleter<ASN1_INTEGER, lib::OpenSSLLib::SSL_ASN1_INTEGER_free>>;
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

using time_point = std::chrono::system_clock::time_point;

/* Below are is the "wrapped" OpenSSL library. By convetion, all functions start with an
 * underscore to visually distinguish them from the methods of the class OpenSSLLib and
 * from the native OpenSSL methods.
 */

/*
 * Retrieve the digest value from ctx and places it in md.
 */
void _EVP_DigestFinal_ex(EVP_MD_CTX* ctx, unsigned char* md, unsigned int* s);

/*
 * Hash cnt bytes of data at d into the digest context ctx.
 */
void _EVP_DigestUpdate(EVP_MD_CTX* ctx, const void* d, size_t cnt);

/*
 * Set up digest context ctx to use a digest type from ENGINE impl.
 */
void _EVP_DigestInit_ex(EVP_MD_CTX* ctx, const EVP_MD* type, ENGINE* impl);

/*
 * Initialize digest context ctx.
 */
void _EVP_MD_CTX_init(EVP_MD_CTX* ctx);

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
SSL_EVP_PKEY_Ptr _EVP_PKEY_keygen(EVP_PKEY_CTX* ctx);

/**
 * Initialize the context for key-generation.
 *
 * @throw OpenSSLException if an error occurs in the underlying OpenSSL function.
 */
void _EVP_PKEY_keygen_init(EVP_PKEY_CTX* ctx);

/**
 * Set the number of bits the RSA key should have.
 *
 * When generating an RSA key with the given context,
 * set the number of bits it should have.
 *
 * @throw OpenSSLException if an error occurs in the underlying OpenSSL function.
 */
void _EVP_PKEY_CTX_set_rsa_keygen_bits(EVP_PKEY_CTX* ctx, int mbits);

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
 * Gets the EC group of a given EC key
 */
const EC_GROUP* _EC_KEY_get0_group(const EC_KEY *key);

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
int _EVP_PKEY_type(const EVP_PKEY* key);

/**
 * Gets the size in bytes of a pkey object
 * @param pkey key to get size from
 * @return the size of provided key
 * @throw OpenSSLException if an error occurs in the underlying OpenSSL function.
 */
int _EVP_PKEY_size(EVP_PKEY *pkey);

/*
 * Thread safe modification of OpenSSL object reference counters.
 *
 * @param pointer A pointer to the reference counter
 * @param amount The value that the reference counter should be changed with.
 *               For example, 1 to increment one or -1 to decrement by one.
 * @param type  The lock type that should be used.
 * @return The new value of the reference counter
 */
int _CRYPTO_add(int *pointer, int amount, int type);

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
void _X509_NAME_add_entry_by_NID(X509_NAME* name,
                                 ASN1_NID nid,
                                 ASN1_Name_Entry_Type type,
                                 std::vector<unsigned char>& bytes);

/**
 * Set the subject-name for the given X509_REQ object.
 *
 * @throw OpenSSLException if an error occurs in the underlying OpenSSL function.
 */
void _X509_REQ_set_subject_name(X509_REQ* req, X509_NAME* name);

/**
 * Set the public key for the given X509_REQ object.
 *
 * @throw OpenSSLException if an error occurs in the underlying OpenSSL function.
 */
void _X509_REQ_set_pubkey(X509_REQ* req, EVP_PKEY* pkey);

/**
 * Set the X509 version for the given X509_REQ object.
 *
 * @throw OpenSSLException if an error occurs in the underlying OpenSSL function.
 */
void _X509_REQ_set_version(X509_REQ* req, unsigned long version);

/**
 * @result pointer to the internal X509_NAME structure.
 *
 * NOTE this result *MUST NOT BE FREED*.
 */
X509_NAME* _X509_REQ_get_subject_name(X509_REQ* req);

/**
 * Get the public key for the given X509_REQ object.
 *
 * @throw OpenSSLException if an error occurs in the underlying OpenSSL function.
 */
SSL_EVP_PKEY_Ptr _X509_REQ_get_public_key(X509_REQ* req);

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
void _PEM_write_bio_X509_REQ(BIO* bio, X509_REQ* req);

/**
 * Write the X509 to PEM format into the given BIO object.
 *
 * @throw OpenSSLException if an error occurs in the underlying OpenSSL function.
 */
void _PEM_write_bio_X509(BIO* bio, X509* x);

/**
 * Read the X509_REQ in PEM format from the given BIO object.
 *
 * @throw OpenSSLException if an error occurs in the underlying OpenSSL function.
 */
SSL_X509_REQ_Ptr _PEM_read_bio_X509_REQ(BIO* bio);

/**
 *
 * We do not use a unique_ptr here because
 * OpenSSL does not provide a free method
 * for this and also makes no mention of if
 * and how this is to be freed.
 *
 * Presumably this points to static memory.
 */
BIO_METHOD* _BIO_s_mem();

/**
 * Create a new BIO instance for the given method.
 */
SSL_BIO_Ptr _BIO_new(BIO_METHOD* method);

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
int _BIO_gets(BIO* bio, std::vector<char>& buf);

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
int _BIO_puts(BIO* bio, std::string buf);

/**
 * Return value of 0 or -1 are possible without inidicating an error.
 * The exact behavior depends on the type of BIO used (i.e. on its
 * method).
 *
 * @param bio The bio object to write to.
 * @param buf The vector from which the data should be written
 *
 * @return The number of characters read, or -1. If -1 is returned, the interpretation
 *      depends on the method of the 'bio' (@see _BIO_new()).
 * @throw OpenSSLException if BIO_gets is not supported for the method of 'bio'
 */
int _BIO_write(BIO* bio, const std::vector<uint8_t> &data);

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
int _BIO_read(BIO* bio, std::vector<uint8_t> &buf, std::size_t numBytes);


/*
 * Read a DER encoded X509 certificate from a bio
 *
 * @throw OpenSSLException if an OpenSSL internal error occurs.
 */
SSL_X509_Ptr _d2i_X509_bio(BIO* bp);
/*
 * Write an X509 certificate in DER encoded form to a bio
 *
 * @throw OpenSSLException if an OpenSSL internal error occurs.
 */
void _i2d_X509_bio(BIO* bp, X509* x);

/**
 * Sign an X509_REQ to obtain a complete CSR.
 *
 * @throw OpenSSLException if an error occurs in the underlying OpenSSL function.
 */
void _X509_REQ_sign_ctx(X509_REQ* req, EVP_MD_CTX* ctx);

/**
 * Enum for the digest types that can be used in signatures
 * or hash computations.
 */
enum class DigestTypes {
    SHA1,
    SHA256, // @MARCUS: Shouldn't there be some value initialization with openssl consts here?
    SHA384,
    SHA512,
    SHA1
};

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
void _EVP_DigestSignInit(EVP_MD_CTX* ctx, DigestTypes md, EVP_PKEY* pkey);

/**
 * Get reference to digest function for a given digest type.
 *
 * @throws std::runtime_error if the requested digest function was not found.
 */
const EVP_MD* _getMDPtrFromDigestType(DigestTypes type);

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
void _PEM_write_bio_PKCS8PrivateKey(BIO* out, EVP_PKEY* pkey, const EVP_CIPHER* cipher,
                                    std::string pwd);
void _PEM_write_bio_PUBKEY(BIO* bp, EVP_PKEY* x);

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
SSL_EVP_PKEY_Ptr _PEM_read_bio_PrivateKey(BIO* bio, std::string pwd);

/**
 * @param bio The BIO instance to read the key from.
 */
SSL_EVP_PKEY_Ptr _PEM_read_bio_PUBKEY(BIO* bio);

/**
 * Read an X509 certificate from BIO instance.
 *
 * @param bio a pointer to a bio instance.
 *
 * @throws OpenSSLException if an internal OpenSSL error is encountered.
 *
 */
SSL_X509_Ptr _PEM_read_bio_X509(BIO*);

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
void _ASN1_TIME_diff(int *pday, int *psec,
                              const ASN1_TIME *from, const ASN1_TIME *to);

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
 *
 * @throw OpenSSLException when an error occurs while initializing
 *                         the context
 */
void _X509_STORE_CTX_init(X509_STORE_CTX *ctx, X509_STORE *store, X509 *x509, STACK_OF(X509) *chain);

/**
 * Get the verification parameters for an X509 store context
 *
 * @param ctx The context
 *
 * @throw OpenSSLException if an error occurs
 */
X509_VERIFY_PARAM* _X509_STORE_CTX_get0_param(X509_STORE_CTX *ctx);

/**
 * @brief Verify if the certificate is a CA
 *
 * @return Whether the certificate is a CA or not
 */
bool _X509_check_ca(X509 *cert);

class X509VerificationFlags {
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
template<class SslType>
SslType *createOpenSSLObject();

template<class SSLSmartPtrType>
SSLSmartPtrType createManagedOpenSSLObject() {
    return SSLSmartPtrType{createOpenSSLObject<typename SSLSmartPtrType::element_type>()};
}

template<class StackType, class ObjType>
void addObjectToStack(StackType *stack, const ObjType *obj);

/**
 * @result pointer to the internal X509_NAME structure.
 *
 * NOTE this result *MUST NOT BE FREED*.
 */
X509_NAME* _X509_get_subject_name(X509 *obj);

/**
 * @result pointer to the internal X509_NAME structure.
 *
 * NOTE this result *MUST NOT BE FREED*.
 */
X509_NAME* _X509_get_issuer_name(X509 *obj);

/**
 * Get not before value of the certificate as system_clock::time_point
 *
 * @throw OpenSSLException if an internal OpenSSL error is encountered
 */
time_point _X509_get_notBefore(X509* x);

/**
 * Get not after value of the certificate as system_clock::time_point
 *
 * @throw OpenSSLException if an internal OpenSSL error is encountered
 */
time_point _X509_get_notAfter(X509* x);

/**
 * Get not before value of the certificate as ASN1_TIME
 *
 * @throw OpenSSLException if an internal OpenSSL error is encountered
 */
ASN1_TIME* _X509_get_notBefore_ASN1(X509* x);

/**
 * Get not after value of the certificate as ASN1_TIME
 *
 * @throw OpenSSLException if an internal OpenSSL error is encountered
 */
ASN1_TIME* _X509_get_notAfter_ASN1(X509* x);

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
SSL_EVP_PKEY_Ptr _X509_get_pubkey(X509* x);

/**
 * Set the subject-name for the given X509 object.
 *
 * @throw OpenSSLException if an error occurs in the underlying OpenSSL function.
 */
void _X509_set_subject_name(X509 *x, X509_NAME* name);

/**
 * Set the issuer-name for the given X509 object.
 *
 * @throw OpenSSLException if an error occurs in the underlying OpenSSL function.
 */
void _X509_set_issuer_name(X509 *x, X509_NAME* name);

/**
 * Set the public key for the given X509 object.
 *
 * @throw OpenSSLException if an error occurs in the underlying OpenSSL function.
 */
void _X509_set_pubkey(X509 *x, EVP_PKEY* key);

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
void _X509_set_notBefore_ASN1(X509 *x, const ASN1_TIME* t);

/**
 * Set not after value of the certificate as ASN1_TIME
 *
 * @throw OpenSSLException if an internal OpenSSL error is encountered
 */
void _X509_set_notAfter_ASN1(X509 *x, const ASN1_TIME* t);

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
std::vector<int> _X509_NAME_get_index_by_NID(X509_NAME* name, ASN1_NID nid);

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
X509_NAME_ENTRY* _X509_NAME_get_entry(X509_NAME *name, int loc);

std::string _X509_NAME_ENTRY_get_data(X509_NAME_ENTRY *entry);

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
SSL_X509_EXTENSION_Ptr _X509V3_EXT_conf_nid(int ext_nid, X509V3_CTX* ctx, std::string value);

/**
 * Sets that there is no configuration database for a context.
 * @param ctx the context which is set
 */
void _X509V3_set_ctx_nodb(X509V3_CTX* ctx);

/**
 * Sets the information within a context.
 * @param ctx the context which is set.
 * @param issuer the issuing certificate for this context
 * @param subject the subject certificate for this context
 */
void _X509V3_set_ctx(X509V3_CTX* ctx, X509* issuer, X509* subject);

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
uint64_t _X509_get_serialNumber(X509* x);

/**
 * Gets the serial number of a certificate with arbitrary precision as a decimal representation in
 * ASCII.
 *
 * @param x the certificate
 * @return the decimal string representation of the serial number
 */
std::string _X509_get_serialNumber_dec(X509* x);

/**
 * Gets the serial number of a certificate with arbitrary precision as a binary representation.
 *
 * @param x the certificate
 * @return the binary representation of the serial number
 */
std::vector<uint8_t> _X509_get_serialNumber_bin(X509* x);

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
SSL_ASN1_TIME_Ptr _ASN1_TIME_copy(const ASN1_TIME* t);

/**
 * Convert an ASN1_TIME object to a C++ time_point
 */
time_point _asn1TimeToTimePoint(const ASN1_TIME *time);

/**
 * Gets the time for the next, planned update for a CRL.
 */
ASN1_TIME* _X509_CRL_get_nextUpdate(const X509_CRL* crl);

/**
 * Gets the time for the creation of a CRL.
 */
ASN1_TIME* _X509_CRL_get_lastUpdate(const X509_CRL* crl);

/**
 * Verifies the signature of a crl with a given public key.
 */
void _X509_CRL_verify(X509_CRL *crl, EVP_PKEY *key);

/**
 * Gets the issuer (the issuer name of the CA certificate) of a CRL.
 */
X509_NAME* _X509_CRL_get_issuer(const X509_CRL* crl);

/**
 * Writes a CRL as PEM encoded to a BIO object.
 */
void _PEM_write_bio_X509_CRL(BIO* bio, X509_CRL* crl);

/**
 * Reads a PEM encoded CRL from a BIO object.
 */
SSL_X509_CRL_Ptr _PEM_read_bio_X509_CRL(BIO* bp);

/**
 * Reads a DER encoded CRL from a BIO object.
 */
SSL_X509_CRL_Ptr _d2i_X509_CRL_bio(BIO* bp);

/**
 * Sets a list of CRLs for a verification context.
 */
void _X509_STORE_CTX_set0_crls(X509_STORE_CTX* ctx, STACK_OF(X509_CRL)* crls);

/**
 * Adds a specific amount of days and seconds to a time_t and returns it as an ASN1_TIME.
 */
SSL_ASN1_TIME_Ptr _ASN1_TIME_adj(std::time_t t, int days, long seconds);

/**
 * Prints an ASN1_STRING to a BIO object.
 */
void _ASN1_STRING_print_ex(BIO* out, const ASN1_STRING* str);

/**
 * Sets the time of verification for a verification context.
 */
void _X509_STORE_CTX_set_time(X509_STORE_CTX* ctx, std::time_t time);

/**
 * Converts an ASN1_TIME to a time_t.
 * @throw OpenSSLException if the ASN1_TIME doesn't fit into a time_t.
 */
time_t _asn1TimeToTimeT(const ASN1_TIME *time);

enum class RSAPaddingMode
{
    NONE = RSA_NO_PADDING,
    PKCS1 = RSA_PKCS1_PADDING,
    PSS = RSA_PKCS1_PSS_PADDING,
    OAEP = RSA_PKCS1_OAEP_PADDING
};

/**
 * Signs a message
 */
void _EVP_PKEY_sign(EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen, const unsigned char *tbs, size_t tbslen);

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
                      const unsigned char *sig, size_t siglen,
                      const unsigned char *tbs, size_t tbslen);

/**
 * Sets the RSA padding
 */
void _EVP_PKEY_CTX_set_rsa_padding(EVP_PKEY_CTX *ctx, int pad);

/**
 * Sets the masking algorithm
 */
void _EVP_PKEY_CTX_set_signature_md(EVP_PKEY_CTX *ctx, const EVP_MD* md);
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
                       unsigned char *out, size_t *outlen,
                       const unsigned char *in, size_t inlen);

/**
 * Initializes the context for an decryption operation
 */
void _EVP_PKEY_decrypt_init(EVP_PKEY_CTX *ctx);

/**
 * Decrypts a message
 */
void _EVP_PKEY_decrypt(EVP_PKEY_CTX *ctx,
                       unsigned char *out, size_t *outlen,
                       const unsigned char *in, size_t inlen);

/**
 * Sets the OAEP hashing function
 */
void _EVP_PKEY_CTX_set_rsa_oaep_md(EVP_PKEY_CTX *ctx, const EVP_MD *md);

/**
 * Sets the OAEP label
 */
void _EVP_PKEY_CTX_set_rsa_oaep_label(EVP_PKEY_CTX *ctx, unsigned char *l, int llen);

/**
 * Gets the OAEP label
 */
int _EVP_PKEY_CTX_get_rsa_oaep_label(EVP_PKEY_CTX *ctx, unsigned char *l);

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
void* _OPENSSL_malloc(int num);

void _CRYPTO_malloc_init();

enum class ellipticCurveNid
{
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
};

}  //::openssl
}  //::mococrw
