/**
 * @file
 * @copyright (C) 2017, BMW AG
 * @copyright (C) 2017, BMW Car IT GmbH
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
template <class T, void(Func)(T*)>
struct SSLDeleter
{
    void operator()(T* ptr) const noexcept
    {
        if (ptr) {
            Func(ptr);
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
using SSL_ASN1_TIME_SharedPTr = utility::SharedPtrTypeFromUniquePtr<SSL_ASN1_TIME_Ptr>;


using time_point = std::chrono::system_clock::time_point;

/* Below are is the "wrapped" OpenSSL library. By convetion, all functions start with an
 * underscore to visually distinguish them from the methods of the class OpenSSLLib and
 * from the native OpenSSL methods.
 */

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
};

enum class ASN1_Name_Entry_Type : int {
    UTF8String = MBSTRING_UTF8,
    ASCIIString = MBSTRING_ASC,
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
    SHA256, // @MARCUS: Shouldn't there be some value initialization with openssl consts here?
    SHA512,
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

class X509VerificationFlags {
public:
    static constexpr unsigned long PARTIAL_CHAIN = X509_V_FLAG_PARTIAL_CHAIN;
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

}  //::openssl
}  //::mococrw
