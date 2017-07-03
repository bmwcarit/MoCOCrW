/**
 * @file
 * @copyright (C) 2017, BMW AG
 * @copyright (C) 2017, BMW Car IT GmbH
 */
#pragma once

#include <memory>
#include <mutex>

#include "mococrw/openssl_lib.h"

namespace mococrw
{
namespace openssl
{
/**
 * Gmock interface.
 *
 * Gmock requires a virtual interface.
 */
class OpenSSLLibMockInterface
{
public:
    virtual const EVP_CIPHER* SSL_EVP_aes_256_cbc() = 0;
    virtual int SSL_BIO_write(BIO* b, const void* buf, int len) = 0;
    virtual int SSL_BIO_read(BIO* b, void* buf, int len) = 0;
    virtual BIO* SSL_BIO_new_file(const char* filename, const char* mode) = 0;
    virtual ~OpenSSLLibMockInterface() = default;

    /* Initialization */
    virtual void SSL_ERR_load_crypto_strings() = 0;
    virtual void SSL_SSL_load_error_strings() = 0;
    virtual void SSL_OpenSSL_add_all_algorithms() = 0;
    virtual void SSL_CRYPTO_malloc_init() = 0;

    /* Key Generation */
    virtual EVP_PKEY* SSL_EVP_PKEY_new() = 0;
    virtual void SSL_EVP_PKEY_free(EVP_PKEY* ptr) = 0;
    virtual int SSL_EVP_PKEY_keygen(EVP_PKEY_CTX* ctx, EVP_PKEY** ppkey) = 0;
    virtual int SSL_EVP_PKEY_keygen_init(EVP_PKEY_CTX* ctx) = 0;

    virtual EVP_PKEY_CTX* SSL_EVP_PKEY_CTX_new_id(int id, ENGINE* engine) = 0;
    virtual void SSL_EVP_PKEY_CTX_free(EVP_PKEY_CTX* ptr) = 0;
    virtual int SSL_EVP_PKEY_CTX_set_rsa_keygen_bits(EVP_PKEY_CTX* ctx, int mbits) = 0;

    virtual int SSL_EVP_PKEY_cmp(const EVP_PKEY *a, const EVP_PKEY *b) = 0;

    /* Reference counting magic */
    virtual int SSL_CRYPTO_add(int *pointer, int amount, int type) = 0;

    /* Error handling */
    virtual char* SSL_ERR_error_string(unsigned long error, char* buf) = 0;
    virtual unsigned long SSL_ERR_get_error() = 0;

    /* X509_NAME related things */
    virtual X509_NAME* SSL_X509_NAME_new() = 0;
    virtual void SSL_X509_NAME_free(X509_NAME*) = 0;
    virtual int SSL_X509_NAME_add_entry_by_NID(X509_NAME* name,
                                               int nid,
                                               int type,
                                               unsigned char* bytes,
                                               int len,
                                               int loc,
                                               int set) = 0;
    virtual int SSL_X509_NAME_get_index_by_NID(X509_NAME* name, int nid, int lastpos) = 0;
    virtual X509_NAME_ENTRY* SSL_X509_NAME_get_entry(X509_NAME* name, int loc) = 0;

    /* X509_NAME_ENTRY */
    virtual ASN1_STRING* SSL_X509_NAME_ENTRY_get_data(X509_NAME_ENTRY* ne) = 0;

    /* ASN1_STRING */
    virtual int SSL_ASN1_STRING_print_ex(BIO* out, ASN1_STRING* str, unsigned long flags) = 0;

    /* X509_REQ */
    virtual void SSL_X509_REQ_free(X509_REQ* ptr) = 0;
    virtual X509_REQ* SSL_X509_REQ_new() = 0;
    virtual int SSL_X509_REQ_set_subject_name(X509_REQ* req, X509_NAME* name) = 0;
    virtual int SSL_X509_REQ_set_pubkey(X509_REQ* x, EVP_PKEY* pkey) = 0;
    virtual int SSL_X509_REQ_set_version(X509_REQ* req, unsigned long version) = 0;
    virtual int SSL_X509_REQ_sign_ctx(X509_REQ*, EVP_MD_CTX*) = 0;
    virtual X509_NAME* SSL_X509_REQ_get_subject_name(X509_REQ* req) = 0;
    virtual EVP_PKEY* SSL_X509_REQ_get_pubkey(X509_REQ *req) = 0;
    virtual int SSL_X509_REQ_verify(X509_REQ *a, EVP_PKEY *r) = 0;

    /* X509 */
    virtual void SSL_X509_free(X509* ptr) = 0;
    virtual X509_NAME* SSL_X509_get_subject_name(X509* ptr) = 0;
    virtual X509_NAME* SSL_X509_get_issuer_name(X509* ptr) = 0;
    virtual EVP_PKEY* SSL_X509_get_pubkey(X509* x) = 0;
    virtual ASN1_TIME* SSL_X509_get_notBefore(X509* x) = 0;
    virtual ASN1_TIME* SSL_X509_get_notAfter(X509* x) = 0;

    /* ASN1_TIME */
    virtual void SSL_ASN1_TIME_free(ASN1_TIME *x) = 0;
    virtual int SSL_ASN1_TIME_diff(int *pday, int *psec,
                              const ASN1_TIME *from, const ASN1_TIME *to) = 0;
    virtual ASN1_TIME *SSL_ASN1_TIME_set(ASN1_TIME *s, time_t t) = 0;

    /* BIO Stuff */
    virtual BIO_METHOD* SSL_BIO_s_mem() = 0;
    virtual void SSL_BIO_free_all(BIO* ptr) = 0;
    virtual BIO* SSL_BIO_new(BIO_METHOD* method) = 0;
    virtual int SSL_BIO_gets(BIO* bio, char* bug, int size) = 0;
    virtual int SSL_BIO_puts(BIO* bio, char* buf) = 0;
    virtual int SSL_PEM_write_bio_X509_REQ(BIO* bio, X509_REQ* req) = 0;
    virtual X509_REQ* SSL_PEM_read_bio_X509_REQ(BIO *bp,
                                         X509_REQ **x,
                                         pem_password_cb *cb,
                                         void *u) = 0;
    virtual int SSL_PEM_write_bio_PKCS8PrivateKey(BIO* bp,
                                                  EVP_PKEY* x,
                                                  const EVP_CIPHER* enc,
                                                  char* kstr,
                                                  int klen,
                                                  pem_password_cb* cb,
                                                  void* u) = 0;
    virtual int SSL_PEM_write_bio_PUBKEY(BIO* bp, EVP_PKEY* x) = 0;
    virtual EVP_PKEY* SSL_PEM_read_bio_PUBKEY(BIO* bio,
                                              EVP_PKEY** pkey,
                                              pem_password_cb* cb,
                                              void* u) = 0;

    virtual EVP_PKEY* SSL_PEM_read_bio_PrivateKey(BIO* bio,
                                                  EVP_PKEY** pkey,
                                                  pem_password_cb* cb,
                                                  void* u) = 0;
    virtual X509* SSL_PEM_read_bio_X509(BIO* bio, X509**, pem_password_cb*, void*) = 0;
    virtual X509 *SSL_d2i_X509_bio(BIO* bp, X509** x509) = 0;
    virtual int SSL_i2d_X509_bio(BIO* bp, X509* x) = 0;

    /* EVP_MD */
    virtual EVP_MD_CTX* SSL_EVP_MD_CTX_create() = 0;
    virtual void SSL_EVP_MD_CTX_destroy(EVP_MD_CTX* ptr) = 0;
    virtual int SSL_EVP_DigestSignInit(
            EVP_MD_CTX* ctx, EVP_PKEY_CTX**, const EVP_MD*, ENGINE*, EVP_PKEY*) = 0;
    virtual const EVP_MD* SSL_EVP_sha256() = 0;
    virtual const EVP_MD* SSL_EVP_sha512() = 0;

    /* X509 Certificate validation */
    virtual X509_STORE* SSL_X509_STORE_new() = 0;
    virtual void SSL_X509_STORE_free(X509_STORE *v) = 0;
    virtual int SSL_X509_STORE_add_cert(X509_STORE *ctx, X509 *x) = 0;

    virtual X509_STORE_CTX* SSL_X509_STORE_CTX_new() = 0;
    virtual void SSL_X509_STORE_CTX_free(X509_STORE_CTX *ctx) = 0;
    virtual int SSL_X509_STORE_CTX_init(X509_STORE_CTX *ctx, X509_STORE *store, X509 *x509,
                                        STACK_OF(X509) *chain) = 0;

    virtual X509_VERIFY_PARAM* SSL_X509_STORE_CTX_get0_param(X509_STORE_CTX *ctx) = 0;
    virtual int SSL_X509_VERIFY_PARAM_set_flags(X509_VERIFY_PARAM *param, unsigned long flags) = 0;

    virtual int SSL_X509_verify_cert(X509_STORE_CTX *ctx) = 0;
    virtual const char* SSL_X509_verify_cert_error_string(long n) = 0;
    virtual int SSL_X509_STORE_CTX_get_error(X509_STORE_CTX *ctx) = 0;

    /* stack of X509 */
    virtual STACK_OF(X509)* SSL_sk_X509_new_null() = 0;
    virtual int SSL_sk_X509_push(STACK_OF(X509)* stack, const X509 *crt) = 0;
    virtual void SSL_sk_X509_free(STACK_OF(X509)* stack) = 0;
};

/**
 * GMock class to mock the above interface.
 *
 */
class OpenSSLLibMock : public OpenSSLLibMockInterface
{
public:
    MOCK_METHOD0(SSL_EVP_aes_256_cbc, const EVP_CIPHER*());
    MOCK_METHOD3(SSL_BIO_write, int(BIO*, const void*, int));
    MOCK_METHOD3(SSL_BIO_read, int(BIO*, void*, int));
    MOCK_METHOD2(SSL_BIO_new_file, BIO*(const char*, const char*));
    MOCK_METHOD0(SSL_ERR_load_crypto_strings, void());
    MOCK_METHOD0(SSL_SSL_load_error_strings, void());
    MOCK_METHOD0(SSL_OpenSSL_add_all_algorithms, void());
    MOCK_METHOD0(SSL_CRYPTO_malloc_init, void());

    MOCK_METHOD1(SSL_X509_REQ_free, void(X509_REQ*));
    MOCK_METHOD0(SSL_X509_REQ_new, X509_REQ*());
    MOCK_METHOD1(SSL_X509_REQ_get_subject_name, X509_NAME*(X509_REQ* req));
    MOCK_METHOD1(SSL_X509_REQ_get_pubkey, EVP_PKEY*(X509_REQ* req));
    MOCK_METHOD2(SSL_X509_REQ_verify, int(X509_REQ *a, EVP_PKEY *r));

    MOCK_METHOD0(SSL_EVP_PKEY_new, EVP_PKEY*());
    MOCK_METHOD1(SSL_EVP_PKEY_free, void(EVP_PKEY*));
    MOCK_METHOD2(SSL_EVP_PKEY_keygen, int(EVP_PKEY_CTX*, EVP_PKEY**));
    MOCK_METHOD1(SSL_EVP_PKEY_keygen_init, int(EVP_PKEY_CTX* ctx));

    MOCK_METHOD2(SSL_EVP_PKEY_CTX_new_id, EVP_PKEY_CTX*(int, ENGINE*));
    MOCK_METHOD1(SSL_EVP_PKEY_CTX_free, void(EVP_PKEY_CTX*));
    MOCK_METHOD2(SSL_EVP_PKEY_CTX_set_rsa_keygen_bits, int(EVP_PKEY_CTX*, int));

    MOCK_METHOD2(SSL_EVP_PKEY_cmp, int(const EVP_PKEY*, const EVP_PKEY *));

    MOCK_METHOD3(SSL_CRYPTO_add, int(int*, int, int));

    MOCK_METHOD0(SSL_ERR_get_error, unsigned long());
    MOCK_METHOD2(SSL_ERR_error_string, char*(unsigned long, char*));

    MOCK_METHOD0(SSL_X509_NAME_new, X509_NAME*());
    MOCK_METHOD1(SSL_X509_NAME_free, void(X509_NAME*));
    MOCK_METHOD7(SSL_X509_NAME_add_entry_by_NID,
                 int(X509_NAME* name,
                     int nid,
                     int type,
                     unsigned char* bytes,
                     int len,
                     int loc,
                     int set));
    MOCK_METHOD2(SSL_X509_REQ_set_subject_name, int(X509_REQ* req, X509_NAME* name));
    MOCK_METHOD2(SSL_X509_REQ_set_pubkey, int(X509_REQ* x, EVP_PKEY* pkey));
    MOCK_METHOD2(SSL_X509_REQ_set_version, int(X509_REQ*, unsigned long));

    MOCK_METHOD0(SSL_BIO_s_mem, BIO_METHOD*());
    MOCK_METHOD1(SSL_BIO_free_all, void(BIO*));
    MOCK_METHOD1(SSL_BIO_new, BIO*(BIO_METHOD*));
    MOCK_METHOD2(SSL_PEM_write_bio_X509_REQ, int(BIO*, X509_REQ*));
    MOCK_METHOD3(SSL_BIO_gets, int(BIO*, char*, int));
    MOCK_METHOD2(SSL_X509_REQ_sign_ctx, int(X509_REQ*, EVP_MD_CTX*));
    MOCK_METHOD0(SSL_EVP_MD_CTX_create, EVP_MD_CTX*());
    MOCK_METHOD5(SSL_EVP_DigestSignInit,
                 int(EVP_MD_CTX* ctx, EVP_PKEY_CTX**, const EVP_MD*, ENGINE*, EVP_PKEY*));
    MOCK_METHOD1(SSL_EVP_MD_CTX_destroy, void(EVP_MD_CTX*));
    MOCK_METHOD0(SSL_EVP_sha256, const EVP_MD*());
    MOCK_METHOD0(SSL_EVP_sha512, const EVP_MD*());
    MOCK_METHOD7(SSL_PEM_write_bio_PKCS8PrivateKey,
                 int(BIO*, EVP_PKEY*, const EVP_CIPHER*, char*, int, pem_password_cb*, void*));
    MOCK_METHOD2(SSL_PEM_write_bio_PUBKEY, int(BIO*, EVP_PKEY*));
    MOCK_METHOD4(SSL_PEM_read_bio_PUBKEY, EVP_PKEY*(BIO*, EVP_PKEY**, pem_password_cb*, void*));
    MOCK_METHOD4(SSL_PEM_read_bio_PrivateKey, EVP_PKEY*(BIO*, EVP_PKEY**, pem_password_cb*, void*));
    MOCK_METHOD2(SSL_BIO_puts, int(BIO*, char*));
    MOCK_METHOD4(SSL_PEM_read_bio_X509_REQ, X509_REQ*(BIO *bp,
                                                      X509_REQ **x,
                                                      pem_password_cb *cb,
                                                      void *u));

    MOCK_METHOD2(SSL_d2i_X509_bio, X509*(BIO*, X509**));
    MOCK_METHOD2(SSL_i2d_X509_bio, int(BIO*, X509*));

    MOCK_METHOD1(SSL_X509_free, void(X509*));
    MOCK_METHOD4(SSL_PEM_read_bio_X509, X509*(BIO* bio, X509**, pem_password_cb*, void*));

    MOCK_METHOD1(SSL_X509_get_subject_name, X509_NAME*(X509*));
    MOCK_METHOD1(SSL_X509_get_issuer_name, X509_NAME*(X509*));
    MOCK_METHOD1(SSL_X509_get_pubkey, EVP_PKEY*(X509*));
    MOCK_METHOD1(SSL_X509_get_notBefore, ASN1_TIME*(X509*));
    MOCK_METHOD1(SSL_X509_get_notAfter, ASN1_TIME*(X509*));

    MOCK_METHOD1(SSL_ASN1_TIME_free, void(ASN1_TIME*));
    MOCK_METHOD4(SSL_ASN1_TIME_diff,int(int*, int*, const ASN1_TIME*, const ASN1_TIME *));
    MOCK_METHOD2(SSL_ASN1_TIME_set, ASN1_TIME*(ASN1_TIME*, time_t));


    MOCK_METHOD0(SSL_X509_STORE_new, X509_STORE*());
    MOCK_METHOD1(SSL_X509_STORE_free, void(X509_STORE*));
    MOCK_METHOD2(SSL_X509_STORE_add_cert, int(X509_STORE*, X509*));

    MOCK_METHOD0(SSL_X509_STORE_CTX_new, X509_STORE_CTX*());
    MOCK_METHOD1(SSL_X509_STORE_CTX_free, void(X509_STORE_CTX*));
    MOCK_METHOD4(SSL_X509_STORE_CTX_init, int(X509_STORE_CTX*, X509_STORE*, X509 *,STACK_OF(X509)*));

    MOCK_METHOD1(SSL_X509_STORE_CTX_get0_param, X509_VERIFY_PARAM*(X509_STORE_CTX*));
    MOCK_METHOD2(SSL_X509_VERIFY_PARAM_set_flags, int(X509_VERIFY_PARAM*, unsigned long));

    MOCK_METHOD1(SSL_X509_verify_cert, int(X509_STORE_CTX*));
    MOCK_METHOD1(SSL_X509_verify_cert_error_string, const char*(long));
    MOCK_METHOD1(SSL_X509_STORE_CTX_get_error, int(X509_STORE_CTX*));

    MOCK_METHOD0(SSL_sk_X509_new_null, STACK_OF(X509)*());
    MOCK_METHOD2(SSL_sk_X509_push, int(STACK_OF(X509)*, const X509*));
    MOCK_METHOD1(SSL_sk_X509_free, void(STACK_OF(X509)*));

    MOCK_METHOD3(SSL_X509_NAME_get_index_by_NID, int(X509_NAME*, int, int));
    MOCK_METHOD2(SSL_X509_NAME_get_entry, X509_NAME_ENTRY*(X509_NAME*, int));
    MOCK_METHOD1(SSL_X509_NAME_ENTRY_get_data, ASN1_STRING*(X509_NAME_ENTRY*));
    MOCK_METHOD3(SSL_ASN1_STRING_print_ex, int(BIO*, ASN1_STRING*, unsigned long));
};

/**
 * Wrap instances of the OpenSSLLibMock
 * inside static members of this class.
 *
 * This gets rid of the need for a singleton and all
 * the realted problems.
 */
class OpenSSLLibMockManager
{
public:
    /**
     * Access the OpenSSLLibMock instance currently
     * maintained. Create a new one, if none is present.
     */
    static OpenSSLLibMock& getMockInterface();

    /**
     * Reset the current OpenSSLLibMock instance
     * maintained within this class.
     */
    static void resetMock();

private:
    static std::unique_ptr<OpenSSLLibMock> _mock;

    /* Unsure how much parallization happens with regard to the tests
     * but let's be safe
     */
    static std::mutex _mutex;
};

}  // ::openssl
}  // ::mococrw
