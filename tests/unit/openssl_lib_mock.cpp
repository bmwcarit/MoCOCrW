/**
 * @file
 * @copyright (C) 2017, BMW AG
 * @copyright (C) 2017, BMW Car IT GmbH
 */

#include <cstddef>

#include <gmock/gmock.h>

#include "openssl_lib_mock.h"
#include "mococrw/openssl_wrap.h"

namespace mococrw
{
namespace openssl
{
std::unique_ptr<OpenSSLLibMock> OpenSSLLibMockManager::_mock{nullptr};
std::mutex OpenSSLLibMockManager::_mutex{};

/*
 * If there is no mock yet, we create a new one.
 */
OpenSSLLibMock& OpenSSLLibMockManager::getMockInterface()
{
    if (!_mock) {
        resetMock();
    }

    return *_mock;
}

void OpenSSLLibMockManager::resetMock()
{
    std::lock_guard<std::mutex> _lock(_mutex);
    _mock = std::make_unique<OpenSSLLibMock>();
}

namespace lib
{
/**
 * Provide implementations for the OpenSSLLib members that forward
 * to the mock object.
 *
 * This translation unit is inserted into the bulid process for unit-tests
 * via CMake. The library gets these definitions from a corresponding class
 * in the src-dir.
 */
// TODO unit test the initialization
void OpenSSLLib::SSL_CRYPTO_malloc_init() noexcept
{
    OpenSSLLibMockManager::getMockInterface().SSL_CRYPTO_malloc_init();
}

void OpenSSLLib::SSL_ERR_load_crypto_strings() noexcept
{
    OpenSSLLibMockManager::getMockInterface().SSL_ERR_load_crypto_strings();
}

void OpenSSLLib::SSL_SSL_load_error_strings() noexcept
{
    OpenSSLLibMockManager::getMockInterface().SSL_SSL_load_error_strings();
}

void OpenSSLLib::SSL_OpenSSL_add_all_algorithms() noexcept
{
    OpenSSLLibMockManager::getMockInterface().SSL_OpenSSL_add_all_algorithms();
}

X509_REQ* OpenSSLLib::SSL_X509_REQ_new() noexcept
{
    return OpenSSLLibMockManager::getMockInterface().SSL_X509_REQ_new();
}

X509_NAME* OpenSSLLib::SSL_X509_REQ_get_subject_name(X509_REQ* req) noexcept
{
    return OpenSSLLibMockManager::getMockInterface().SSL_X509_REQ_get_subject_name(req);
}

EVP_PKEY* OpenSSLLib::SSL_X509_REQ_get_pubkey(X509_REQ *req) noexcept
{
    return OpenSSLLibMockManager::getMockInterface().SSL_X509_REQ_get_pubkey(req);
}

int OpenSSLLib::SSL_X509_REQ_verify(X509_REQ *a, EVP_PKEY *r) noexcept
{
    return OpenSSLLibMockManager::getMockInterface().SSL_X509_REQ_verify(a, r);
}

void OpenSSLLib::SSL_X509_REQ_free(X509_REQ* ptr) noexcept
{
    OpenSSLLibMockManager::getMockInterface().SSL_X509_REQ_free(ptr);
}

EVP_PKEY* OpenSSLLib::SSL_EVP_PKEY_new() noexcept
{
    return OpenSSLLibMockManager::getMockInterface().SSL_EVP_PKEY_new();
}

void OpenSSLLib::SSL_EVP_PKEY_free(EVP_PKEY* ptr) noexcept
{
    OpenSSLLibMockManager::getMockInterface().SSL_EVP_PKEY_free(ptr);
}

int OpenSSLLib::SSL_EVP_PKEY_keygen(EVP_PKEY_CTX* ctx, EVP_PKEY** ppkey) noexcept
{
    return OpenSSLLibMockManager::getMockInterface().SSL_EVP_PKEY_keygen(ctx, ppkey);
}

int OpenSSLLib::SSL_EVP_PKEY_keygen_init(EVP_PKEY_CTX* ctx) noexcept
{
    return OpenSSLLibMockManager::getMockInterface().SSL_EVP_PKEY_keygen_init(ctx);
}

EVP_PKEY_CTX* OpenSSLLib::SSL_EVP_PKEY_CTX_new_id(int id, ENGINE* engine) noexcept
{
    return OpenSSLLibMockManager::getMockInterface().SSL_EVP_PKEY_CTX_new_id(id, engine);
}

void OpenSSLLib::SSL_EVP_PKEY_CTX_free(EVP_PKEY_CTX* ptr) noexcept
{
    return OpenSSLLibMockManager::getMockInterface().SSL_EVP_PKEY_CTX_free(ptr);
}

int OpenSSLLib::SSL_EVP_PKEY_CTX_set_rsa_keygen_bits(EVP_PKEY_CTX* ctx, int mbits) noexcept
{
    return OpenSSLLibMockManager::getMockInterface().SSL_EVP_PKEY_CTX_set_rsa_keygen_bits(ctx,
                                                                                          mbits);
}

int OpenSSLLib::SSL_EVP_PKEY_cmp(const EVP_PKEY *a, const EVP_PKEY *b) noexcept
{
    return OpenSSLLibMockManager::getMockInterface().SSL_EVP_PKEY_cmp(a,b);
}

/* Reference counting magic */
int OpenSSLLib::SSL_CRYPTO_add(int *pointer, int amount, int type) noexcept {
    return OpenSSLLibMockManager::getMockInterface().SSL_CRYPTO_add(pointer, amount, type);
}

char* OpenSSLLib::SSL_ERR_error_string(unsigned long error, char* buf) noexcept
{
    return OpenSSLLibMockManager::getMockInterface().SSL_ERR_error_string(error, buf);
}

unsigned long OpenSSLLib::SSL_ERR_get_error() noexcept
{
    return OpenSSLLibMockManager::getMockInterface().SSL_ERR_get_error();
}

X509_NAME* OpenSSLLib::SSL_X509_NAME_new() noexcept
{
    return OpenSSLLibMockManager::getMockInterface().SSL_X509_NAME_new();
}

void OpenSSLLib::SSL_X509_NAME_free(X509_NAME* ptr) noexcept
{
    OpenSSLLibMockManager::getMockInterface().SSL_X509_NAME_free(ptr);
}

int OpenSSLLib::SSL_X509_NAME_add_entry_by_NID(X509_NAME* name,
                                               int nid,
                                               int type,
                                               unsigned char* bytes,
                                               int len,
                                               int loc,
                                               int set) noexcept
{
    return OpenSSLLibMockManager::getMockInterface().SSL_X509_NAME_add_entry_by_NID(
            name, nid, type, bytes, len, loc, set);
}

int OpenSSLLib::SSL_X509_REQ_set_subject_name(X509_REQ* req, X509_NAME* name) noexcept
{
    return OpenSSLLibMockManager::getMockInterface().SSL_X509_REQ_set_subject_name(req, name);
}

int OpenSSLLib::SSL_X509_REQ_set_pubkey(X509_REQ* req, EVP_PKEY* pkey) noexcept
{
    return OpenSSLLibMockManager::getMockInterface().SSL_X509_REQ_set_pubkey(req, pkey);
}

int OpenSSLLib::SSL_X509_REQ_set_version(X509_REQ* ctx, unsigned long version) noexcept
{
    return OpenSSLLibMockManager::getMockInterface().SSL_X509_REQ_set_version(ctx, version);
}

int OpenSSLLib::SSL_PEM_write_bio_X509_REQ(BIO* bio, X509_REQ* req) noexcept
{
    return OpenSSLLibMockManager::getMockInterface().SSL_PEM_write_bio_X509_REQ(bio, req);
}

X509_REQ* OpenSSLLib::SSL_PEM_read_bio_X509_REQ(BIO *bp,
                                         X509_REQ **x,
                                         pem_password_cb *cb,
                                         void *u) noexcept
{
    return OpenSSLLibMockManager::getMockInterface().SSL_PEM_read_bio_X509_REQ(bp, x, cb, u);
}

BIO_METHOD* OpenSSLLib::SSL_BIO_s_mem() noexcept
{
    return OpenSSLLibMockManager::getMockInterface().SSL_BIO_s_mem();
}

void OpenSSLLib::SSL_BIO_free_all(BIO* ptr) noexcept
{
    OpenSSLLibMockManager::getMockInterface().SSL_BIO_free_all(ptr);
}

BIO* OpenSSLLib::SSL_BIO_new(BIO_METHOD* method) noexcept
{
    return OpenSSLLibMockManager::getMockInterface().SSL_BIO_new(method);
}

int OpenSSLLib::SSL_BIO_gets(BIO* bio, char* buf, int size) noexcept
{
    return OpenSSLLibMockManager::getMockInterface().SSL_BIO_gets(bio, buf, size);
}

int OpenSSLLib::SSL_BIO_puts(BIO* bio, char* buf) noexcept
{
    return OpenSSLLibMockManager::getMockInterface().SSL_BIO_puts(bio, buf);
}

int OpenSSLLib::SSL_X509_REQ_sign_ctx(X509_REQ* req, EVP_MD_CTX* ctx) noexcept
{
    return OpenSSLLibMockManager::getMockInterface().SSL_X509_REQ_sign_ctx(req, ctx);
}

EVP_MD_CTX* OpenSSLLib::SSL_EVP_MD_CTX_create() noexcept
{
    return OpenSSLLibMockManager::getMockInterface().SSL_EVP_MD_CTX_create();
}

int OpenSSLLib::SSL_EVP_DigestSignInit(EVP_MD_CTX* ctx,
                                       EVP_PKEY_CTX** pctx,
                                       const EVP_MD* type,
                                       ENGINE* e,
                                       EVP_PKEY* pkey) noexcept
{
    return OpenSSLLibMockManager::getMockInterface().SSL_EVP_DigestSignInit(
            ctx, pctx, type, e, pkey);
}

void OpenSSLLib::SSL_EVP_MD_CTX_destroy(EVP_MD_CTX* ptr) noexcept
{
    OpenSSLLibMockManager::getMockInterface().SSL_EVP_MD_CTX_destroy(ptr);
}

const EVP_MD* OpenSSLLib::SSL_EVP_sha256() noexcept
{
    return OpenSSLLibMockManager::getMockInterface().SSL_EVP_sha256();
}

const EVP_MD* OpenSSLLib::SSL_EVP_sha512() noexcept
{
    return OpenSSLLibMockManager::getMockInterface().SSL_EVP_sha512();
}

int OpenSSLLib::SSL_PEM_write_bio_PKCS8PrivateKey(BIO* bp,
                                                  EVP_PKEY* x,
                                                  const EVP_CIPHER* enc,
                                                  char* kstr,
                                                  int klen,
                                                  pem_password_cb* cb,
                                                  void* u) noexcept
{
    return OpenSSLLibMockManager::getMockInterface().SSL_PEM_write_bio_PKCS8PrivateKey(
            bp, x, enc, kstr, klen, cb, u);
}

int OpenSSLLib::SSL_PEM_write_bio_PUBKEY(BIO* bp, EVP_PKEY* x) noexcept
{
    return OpenSSLLibMockManager::getMockInterface().SSL_PEM_write_bio_PUBKEY(bp, x);
}
EVP_PKEY* OpenSSLLib::SSL_PEM_read_bio_PUBKEY(BIO* bio,
                                              EVP_PKEY** pkey,
                                              pem_password_cb* cb,
                                              void* u) noexcept
{
    return OpenSSLLibMockManager::getMockInterface().SSL_PEM_read_bio_PUBKEY(bio, pkey, cb, u);
}

EVP_PKEY* OpenSSLLib::SSL_PEM_read_bio_PrivateKey(BIO* bio,
                                                  EVP_PKEY** pkey,
                                                  pem_password_cb* cb,
                                                  void* u) noexcept
{
    return OpenSSLLibMockManager::getMockInterface().SSL_PEM_read_bio_PrivateKey(bio, pkey, cb, u);
}

X509 *OpenSSLLib::SSL_d2i_X509_bio(BIO* bp, X509** x509) noexcept
{
    return OpenSSLLibMockManager::getMockInterface().SSL_d2i_X509_bio(bp, x509);
}

int OpenSSLLib::SSL_i2d_X509_bio(BIO* bp, X509* x) noexcept
{
    return OpenSSLLibMockManager::getMockInterface().SSL_i2d_X509_bio(bp, x);
}

void OpenSSLLib::SSL_X509_free(X509* ptr) noexcept
{
    OpenSSLLibMockManager::getMockInterface().SSL_X509_free(ptr);
}

X509* OpenSSLLib::SSL_PEM_read_bio_X509(BIO* bio, X509** x, pem_password_cb* cb, void* pwd) noexcept
{
    return OpenSSLLibMockManager::getMockInterface().SSL_PEM_read_bio_X509(bio, x, cb, pwd);
}

void OpenSSLLib::SSL_ASN1_TIME_free(ASN1_TIME *x) noexcept
{
    return OpenSSLLibMockManager::getMockInterface().SSL_ASN1_TIME_free(x);
}

int OpenSSLLib::SSL_ASN1_TIME_diff(int *pday, int *psec,
                              const ASN1_TIME *from, const ASN1_TIME *to) noexcept
{
    return OpenSSLLibMockManager::getMockInterface().SSL_ASN1_TIME_diff(pday, psec, from, to);
}

ASN1_TIME *OpenSSLLib::SSL_ASN1_TIME_set(ASN1_TIME *s, time_t t) noexcept
{
    return OpenSSLLibMockManager::getMockInterface().SSL_ASN1_TIME_set(s,t);
}

/* X509 */
X509_NAME* OpenSSLLib::SSL_X509_get_subject_name(X509 *ptr) noexcept
{
    return OpenSSLLibMockManager::getMockInterface().SSL_X509_get_subject_name(ptr);
}

X509_NAME* OpenSSLLib::SSL_X509_get_issuer_name(X509 *ptr) noexcept
{
    return OpenSSLLibMockManager::getMockInterface().SSL_X509_get_issuer_name(ptr);
}

EVP_PKEY* OpenSSLLib::SSL_X509_get_pubkey(X509 *x) noexcept
{
    return OpenSSLLibMockManager::getMockInterface().SSL_X509_get_pubkey(x);
}

ASN1_TIME* OpenSSLLib::SSL_X509_get_notBefore(X509* x) noexcept
{
    return OpenSSLLibMockManager::getMockInterface().SSL_X509_get_notBefore(x);
}

ASN1_TIME* OpenSSLLib::SSL_X509_get_notAfter(X509* x) noexcept
{
    return OpenSSLLibMockManager::getMockInterface().SSL_X509_get_notAfter(x);
}

/* X509 Certificate validation */
X509_STORE* OpenSSLLib::SSL_X509_STORE_new() noexcept { return OpenSSLLibMockManager::getMockInterface().SSL_X509_STORE_new(); }

void OpenSSLLib::SSL_X509_STORE_free(X509_STORE *v) noexcept { OpenSSLLibMockManager::getMockInterface().SSL_X509_STORE_free(v); }

int OpenSSLLib::SSL_X509_STORE_add_cert(X509_STORE *ctx, X509 *x) noexcept
{
    return OpenSSLLibMockManager::getMockInterface().SSL_X509_STORE_add_cert(ctx,x);
}

X509_STORE_CTX* OpenSSLLib::SSL_X509_STORE_CTX_new() noexcept
{
    return OpenSSLLibMockManager::getMockInterface().SSL_X509_STORE_CTX_new();
}

void OpenSSLLib::SSL_X509_STORE_CTX_free(X509_STORE_CTX *ctx) noexcept
{
    OpenSSLLibMockManager::getMockInterface().SSL_X509_STORE_CTX_free(ctx);
}
int OpenSSLLib::SSL_X509_STORE_CTX_init(X509_STORE_CTX *ctx, X509_STORE *store, X509 *x509,
                                        STACK_OF(X509) *chain) noexcept
{
    return OpenSSLLibMockManager::getMockInterface().SSL_X509_STORE_CTX_init(ctx,store,x509,chain);
}

X509_VERIFY_PARAM* OpenSSLLib::SSL_X509_STORE_CTX_get0_param(X509_STORE_CTX *ctx) noexcept
{
    return OpenSSLLibMockManager::getMockInterface().SSL_X509_STORE_CTX_get0_param(ctx);
}

int OpenSSLLib::SSL_X509_VERIFY_PARAM_set_flags(X509_VERIFY_PARAM *param, unsigned long flags) noexcept
{
    return OpenSSLLibMockManager::getMockInterface().SSL_X509_VERIFY_PARAM_set_flags(param, flags);
}


int OpenSSLLib::SSL_X509_verify_cert(X509_STORE_CTX *ctx) noexcept {
    return OpenSSLLibMockManager::getMockInterface().SSL_X509_verify_cert(ctx);
}

const char* OpenSSLLib::SSL_X509_verify_cert_error_string(long n) noexcept {
    return OpenSSLLibMockManager::getMockInterface().SSL_X509_verify_cert_error_string(n);
}

int OpenSSLLib::SSL_X509_STORE_CTX_get_error(X509_STORE_CTX *ctx) noexcept {
    return OpenSSLLibMockManager::getMockInterface().SSL_X509_STORE_CTX_get_error(ctx);
}

/* stack of X509 */
STACK_OF(X509)* OpenSSLLib::SSL_sk_X509_new_null() noexcept
{
    return OpenSSLLibMockManager::getMockInterface().SSL_sk_X509_new_null();
}

int OpenSSLLib::SSL_sk_X509_push(STACK_OF(X509)* stack, const X509 *crt)  noexcept
{
    return OpenSSLLibMockManager::getMockInterface().SSL_sk_X509_push(stack, crt);
}
void OpenSSLLib::SSL_sk_X509_free(STACK_OF(X509)* stack) noexcept
{
    return OpenSSLLibMockManager::getMockInterface().SSL_sk_X509_free(stack);
}

int OpenSSLLib::SSL_X509_NAME_get_index_by_NID(X509_NAME* name,
                                                        int nid,
                                                        int lastpos) noexcept
{
    return OpenSSLLibMockManager::getMockInterface().SSL_X509_NAME_get_index_by_NID(name, nid, lastpos);
}

X509_NAME_ENTRY* OpenSSLLib::SSL_X509_NAME_get_entry(X509_NAME* name, int loc) noexcept
{
    return OpenSSLLibMockManager::getMockInterface().SSL_X509_NAME_get_entry(name, loc);
}

ASN1_STRING * OpenSSLLib::SSL_X509_NAME_ENTRY_get_data(X509_NAME_ENTRY *ne) noexcept
{
    return OpenSSLLibMockManager::getMockInterface().SSL_X509_NAME_ENTRY_get_data(ne);
}

int OpenSSLLib::SSL_ASN1_STRING_print_ex(BIO *out, ASN1_STRING *str, unsigned long flags) noexcept
{
    return OpenSSLLibMockManager::getMockInterface().SSL_ASN1_STRING_print_ex(out, str, flags);
}

BIO* OpenSSLLib::SSL_BIO_new_file(const char* filename, const char* mode) noexcept
{
    return OpenSSLLibMockManager::getMockInterface().SSL_BIO_new_file(filename, mode);
}
int OpenSSLLib::SSL_BIO_read(BIO* b, void* buf, int len) noexcept
{
    return OpenSSLLibMockManager::getMockInterface().SSL_BIO_read(b, buf, len);
}
int OpenSSLLib::SSL_BIO_write(BIO* b, const void* buf, int len) noexcept
{
    return OpenSSLLibMockManager::getMockInterface().SSL_BIO_write(b, buf, len);
}
const EVP_CIPHER* OpenSSLLib::SSL_EVP_aes_256_cbc() noexcept
{
    return OpenSSLLibMockManager::getMockInterface().SSL_EVP_aes_256_cbc();
}
}  //::lib
}  //::openssl
}  //::mococrw
