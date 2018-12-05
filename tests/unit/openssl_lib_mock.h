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
    virtual int SSL_EVP_MD_CTX_cleanup(EVP_MD_CTX* ctx) = 0;
    virtual int SSL_EVP_DigestFinal_ex(EVP_MD_CTX* ctx, unsigned char* md, unsigned int* s) = 0;
    virtual int SSL_EVP_DigestUpdate(EVP_MD_CTX* ctx, const void* d, size_t cnt) = 0;
    virtual int SSL_EVP_DigestInit_ex(EVP_MD_CTX* ctx, const EVP_MD* type, ENGINE* impl) = 0;
    virtual void SSL_EVP_MD_CTX_init(EVP_MD_CTX* ctx) = 0;
    virtual void SSL_X509_STORE_CTX_set_time(X509_STORE_CTX* ctx, unsigned long flags, time_t t) = 0;
    virtual ASN1_TIME* SSL_ASN1_TIME_adj(ASN1_TIME* s, time_t t, int offset_day, long offset_sec) = 0;
    virtual int SSL_sk_X509_CRL_push(STACK_OF(X509_CRL)* stack, const X509_CRL* crl) = 0;
    virtual STACK_OF(X509_CRL)* SSL_sk_X509_CRL_new_null() = 0;
    virtual void SSL_sk_X509_CRL_free(STACK_OF(X509_CRL)* stack) = 0;
    virtual void SSL_X509_STORE_CTX_set0_crls(X509_STORE_CTX* ctx, STACK_OF(X509_CRL)* crls) = 0;
    virtual X509_CRL* SSL_X509_CRL_new() = 0;
    virtual void SSL_X509_CRL_free(X509_CRL* a) = 0;
    virtual X509_CRL* SSL_d2i_X509_CRL_bio(BIO* bp, X509_CRL** crl) = 0;
    virtual int SSL_PEM_write_bio_X509_CRL(BIO* bp, X509_CRL* x) = 0;
    virtual X509_CRL* SSL_PEM_read_bio_X509_CRL(BIO* bp, X509_CRL** x, pem_password_cb* cb, void* u) = 0;
    virtual ASN1_TIME* SSL_X509_CRL_get_lastUpdate(const X509_CRL* x) = 0;
    virtual ASN1_TIME* SSL_X509_CRL_get_nextUpdate(const X509_CRL* x) = 0;
    virtual int SSL_X509_CRL_verify(X509_CRL* a, EVP_PKEY* r) = 0;
    virtual X509_NAME* SSL_X509_CRL_get_issuer(const X509_CRL* crl) = 0;
    virtual ASN1_STRING* SSL_ASN1_STRING_dup(const ASN1_STRING* str) = 0;
    virtual ASN1_TIME* SSL_ASN1_TIME_new() = 0;
    virtual int SSL_ASN1_TIME_set_string(ASN1_TIME* s, const char* str) = 0;
    virtual int SSL_BN_num_bytes(const BIGNUM* a) = 0;
    virtual int SSL_BN_bn2bin(const BIGNUM* a, unsigned char* to) = 0;
    virtual ASN1_INTEGER* SSL_ASN1_INTEGER_new() = 0;
    virtual void SSL_ASN1_INTEGER_free(ASN1_INTEGER* a) = 0;
    virtual void* SSL_OPENSSL_malloc(int num) = 0;
    virtual void SSL_OPENSSL_free(void* addr) = 0;
    virtual char* SSL_BN_bn2dec(const BIGNUM* a) = 0;
    virtual void SSL_BN_free(BIGNUM* a) = 0;
    virtual BIGNUM* SSL_ASN1_INTEGER_to_BN(const ASN1_INTEGER* ai, BIGNUM* bn) = 0;
    virtual int SSL_ASN1_INTEGER_cmp(const ASN1_INTEGER* x, const ASN1_INTEGER* y) = 0;
    virtual long SSL_ASN1_INTEGER_get(const ASN1_INTEGER* a) = 0;
    virtual int SSL_ASN1_INTEGER_set(ASN1_INTEGER* a, long value) = 0;
    virtual ASN1_INTEGER* SSL_X509_get_serialNumber(X509* x) = 0;
    virtual int SSL_X509_set_serialNumber(X509* x, ASN1_INTEGER* serial) = 0;
    virtual void SSL_X509V3_set_ctx(X509V3_CTX* ctx, X509* issuer, X509* subject, X509_REQ* req, X509_CRL* crl, int flags) = 0;
    virtual void SSL_X509V3_set_ctx_nodb(X509V3_CTX* ctx) = 0;
    virtual void SSL_X509_EXTENSION_free(X509_EXTENSION* a) = 0;
    virtual int SSL_X509_add_ext(X509* x, X509_EXTENSION* ex, int loc) = 0;
    virtual X509_EXTENSION* SSL_X509V3_EXT_conf_nid(lhash_st_CONF_VALUE* conf,
                                                    X509V3_CTX* ctx,
                                                    int ext_nid,
                                                    char* value) = 0;
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

    virtual EVP_PKEY_CTX* SSL_EVP_PKEY_CTX_new(EVP_PKEY *pkey, ENGINE* engine) = 0;
    virtual EVP_PKEY_CTX* SSL_EVP_PKEY_CTX_new_id(int id, ENGINE* engine) = 0;
    virtual void SSL_EVP_PKEY_CTX_free(EVP_PKEY_CTX* ptr) = 0;
    virtual int SSL_EVP_PKEY_CTX_set_rsa_keygen_bits(EVP_PKEY_CTX* ctx, int mbits) = 0;

    virtual int SSL_EVP_PKEY_cmp(const EVP_PKEY *a, const EVP_PKEY *b) = 0;

    virtual int SSL_EVP_PKEY_paramgen_init(EVP_PKEY_CTX *ctx) = 0;
    virtual int SSL_EVP_PKEY_paramgen(EVP_PKEY_CTX *ctx, EVP_PKEY **ppkey) = 0;
    virtual int SSL_EVP_PKEY_CTX_set_ec_paramgen_curve_nid(EVP_PKEY_CTX *ctx, int nid) = 0;
    virtual int SSL_EVP_PKEY_CTX_set_ec_param_enc(EVP_PKEY_CTX *ctx, int param_enc) = 0;
    virtual const EC_GROUP* SSL_EC_KEY_get0_group(const EC_KEY *key) = 0;
    virtual int SSL_EC_GROUP_get_curve_name(const EC_GROUP *group) = 0;
    virtual int SSL_EVP_PKEY_type(int type) = 0;
    virtual int SSL_EVP_PKEY_size(EVP_PKEY *pkey) = 0;

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
    virtual X509* SSL_X509_new() = 0;
    virtual int SSL_X509_set_pubkey(X509* ptr, EVP_PKEY* pkey) = 0;
    virtual int SSL_X509_set_issuer_name(X509 *x, X509_NAME *name) = 0;
    virtual int SSL_X509_set_subject_name(X509 *x, X509_NAME *name) = 0;
    virtual int SSL_X509_set_notBefore(X509 *x, const ASN1_TIME* t) = 0;
    virtual int SSL_X509_set_notAfter(X509 *x, const ASN1_TIME* t) = 0;
    virtual int SSL_X509_sign(X509 *x, EVP_PKEY *pkey, const EVP_MD *md) = 0;
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
    virtual int SSL_PEM_write_bio_X509(BIO *bp, X509 *x) = 0;
    virtual X509 *SSL_d2i_X509_bio(BIO* bp, X509** x509) = 0;
    virtual int SSL_i2d_X509_bio(BIO* bp, X509* x) = 0;

    /* EVP_MD */
    virtual EVP_MD_CTX* SSL_EVP_MD_CTX_create() = 0;
    virtual void SSL_EVP_MD_CTX_destroy(EVP_MD_CTX* ptr) = 0;
    virtual int SSL_EVP_DigestSignInit(
            EVP_MD_CTX* ctx, EVP_PKEY_CTX**, const EVP_MD*, ENGINE*, EVP_PKEY*) = 0;
    virtual const EVP_MD* SSL_EVP_sha1() = 0;
    virtual const EVP_MD* SSL_EVP_sha256() = 0;
    virtual const EVP_MD* SSL_EVP_sha384() = 0;
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

    virtual int SSL_X509_check_ca(X509 *cert) = 0;

    /* stack of X509 */
    virtual STACK_OF(X509)* SSL_sk_X509_new_null() = 0;
    virtual int SSL_sk_X509_push(STACK_OF(X509)* stack, const X509 *crt) = 0;
    virtual void SSL_sk_X509_free(STACK_OF(X509)* stack) = 0;

    /* Signatures */
    virtual int SSL_EVP_PKEY_sign(EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen, const unsigned char *tbs, size_t tbslen) = 0;
    virtual int SSL_EVP_PKEY_sign_init(EVP_PKEY_CTX *ctx) = 0;
    virtual int SSL_EVP_PKEY_verify_init(EVP_PKEY_CTX *ctx) = 0;
    virtual int SSL_EVP_PKEY_verify(EVP_PKEY_CTX *ctx,
                               const unsigned char *sig, size_t siglen,
                               const unsigned char *tbs, size_t tbslen) = 0;
    virtual int SSL_EVP_PKEY_CTX_set_rsa_padding(EVP_PKEY_CTX *ctx, int pad) = 0;
    virtual int SSL_EVP_PKEY_CTX_set_signature_md(EVP_PKEY_CTX *ctx, const EVP_MD* md) = 0;
    virtual int SSL_EVP_PKEY_CTX_set_rsa_pss_saltlen(EVP_PKEY_CTX *ctx, int len) = 0;
    virtual int SSL_EVP_PKEY_CTX_set_rsa_mgf1_md(EVP_PKEY_CTX *ctx, const EVP_MD *md) = 0;

    /* Encryption */
    virtual int SSL_EVP_PKEY_encrypt_init(EVP_PKEY_CTX *ctx) = 0;
    virtual int SSL_EVP_PKEY_encrypt(EVP_PKEY_CTX *ctx,
                                    unsigned char *out, size_t *outlen,
                                    const unsigned char *in, size_t inlen) = 0;
    virtual int SSL_EVP_PKEY_decrypt_init(EVP_PKEY_CTX *ctx) = 0;
    virtual int SSL_EVP_PKEY_decrypt(EVP_PKEY_CTX *ctx,
                                    unsigned char *out, size_t *outlen,
                                    const unsigned char *in, size_t inlen) = 0;
    virtual int SSL_EVP_PKEY_CTX_set_rsa_oaep_md(EVP_PKEY_CTX *ctx, const EVP_MD *md) = 0;
    virtual int SSL_EVP_PKEY_CTX_set_rsa_oaep_label(EVP_PKEY_CTX *ctx, unsigned char *l,
                                                    int llen) = 0;
    virtual int SSL_EVP_PKEY_CTX_get_rsa_oaep_label(EVP_PKEY_CTX *ctx, unsigned char *l) = 0;
    virtual int SSL_RSA_size(const RSA *r) = 0;
    virtual int SSL_EVP_MD_size(const EVP_MD *md) = 0;
};

/**
 * GMock class to mock the above interface.
 *
 */
class OpenSSLLibMock : public OpenSSLLibMockInterface
{
public:
    MOCK_METHOD1(SSL_EVP_MD_CTX_cleanup, int(EVP_MD_CTX*));
    MOCK_METHOD3(SSL_EVP_DigestFinal_ex, int(EVP_MD_CTX*, unsigned char*, unsigned int*));
    MOCK_METHOD3(SSL_EVP_DigestUpdate, int(EVP_MD_CTX*, const void*, size_t));
    MOCK_METHOD3(SSL_EVP_DigestInit_ex, int(EVP_MD_CTX*, const EVP_MD*, ENGINE*));
    MOCK_METHOD1(SSL_EVP_MD_CTX_init, void(EVP_MD_CTX*));
    MOCK_METHOD3(SSL_X509_STORE_CTX_set_time, void(X509_STORE_CTX*, unsigned long, time_t));
    MOCK_METHOD4(SSL_ASN1_TIME_adj, ASN1_TIME*(ASN1_TIME*, time_t, int, long));
    MOCK_METHOD2(SSL_sk_X509_CRL_push, int(STACK_OF(X509_CRL)*, const X509_CRL*));
    MOCK_METHOD0(SSL_sk_X509_CRL_new_null, STACK_OF(X509_CRL)*());
    MOCK_METHOD1(SSL_sk_X509_CRL_free, void(STACK_OF(X509_CRL)*));
    MOCK_METHOD2(SSL_X509_STORE_CTX_set0_crls, void(X509_STORE_CTX*, STACK_OF(X509_CRL)*));
    MOCK_METHOD1(SSL_sk_X509_REVOKED_num, int(STACK_OF(X509_REVOKED)*));
    MOCK_METHOD2(SSL_sk_X509_REVOKED_value, X509_REVOKED*(STACK_OF(X509_REVOKED)*, int));
    MOCK_METHOD0(SSL_X509_CRL_new, X509_CRL*());
    MOCK_METHOD1(SSL_X509_CRL_free, void(X509_CRL*));
    MOCK_METHOD2(SSL_d2i_X509_CRL_bio, X509_CRL*(BIO*, X509_CRL**));
    MOCK_METHOD2(SSL_PEM_write_bio_X509_CRL, int(BIO*, X509_CRL*));
    MOCK_METHOD4(SSL_PEM_read_bio_X509_CRL, X509_CRL*(BIO*, X509_CRL**, pem_password_cb*, void*));
    MOCK_METHOD1(SSL_X509_CRL_get_REVOKED, STACK_OF(X509_REVOKED)*(X509_CRL*));
    MOCK_METHOD1(SSL_X509_CRL_get_lastUpdate, ASN1_TIME*(const X509_CRL*));
    MOCK_METHOD1(SSL_X509_CRL_get_nextUpdate, ASN1_TIME*(const X509_CRL*));
    MOCK_METHOD2(SSL_X509_CRL_verify, int(X509_CRL*, EVP_PKEY*));
    MOCK_METHOD1(SSL_X509_CRL_get_issuer, X509_NAME*(const X509_CRL*));
    MOCK_METHOD1(SSL_ASN1_STRING_dup, ASN1_STRING*(const ASN1_STRING*));
    MOCK_METHOD0(SSL_ASN1_TIME_new, ASN1_TIME*());
    MOCK_METHOD2(SSL_ASN1_TIME_set_string, int(ASN1_TIME*, const char*));
    MOCK_METHOD1(SSL_BN_num_bytes, int(const BIGNUM*));
    MOCK_METHOD2(SSL_BN_bn2bin, int(const BIGNUM*, unsigned char*));
    MOCK_METHOD0(SSL_ASN1_INTEGER_new, ASN1_INTEGER*());
    MOCK_METHOD1(SSL_ASN1_INTEGER_free, void(ASN1_INTEGER*));
    MOCK_METHOD1(SSL_OPENSSL_malloc, void*(int));
    MOCK_METHOD1(SSL_OPENSSL_free, void(void*));
    MOCK_METHOD1(SSL_BN_bn2dec, char*(const BIGNUM*));
    MOCK_METHOD1(SSL_BN_free, void(BIGNUM*));
    MOCK_METHOD2(SSL_ASN1_INTEGER_to_BN, BIGNUM*(const ASN1_INTEGER*, BIGNUM*));
    MOCK_METHOD2(SSL_ASN1_INTEGER_cmp, int(const ASN1_INTEGER*, const ASN1_INTEGER*));
    MOCK_METHOD1(SSL_ASN1_INTEGER_get, long(const ASN1_INTEGER*));
    MOCK_METHOD2(SSL_ASN1_INTEGER_set, int(ASN1_INTEGER*, long));
    MOCK_METHOD1(SSL_X509_get_serialNumber, ASN1_INTEGER*(X509*));
    MOCK_METHOD2(SSL_X509_set_serialNumber, int(X509*, ASN1_INTEGER*));
    MOCK_METHOD6(SSL_X509V3_set_ctx, void(X509V3_CTX*, X509*, X509*, X509_REQ*, X509_CRL*, int));
    MOCK_METHOD1(SSL_X509V3_set_ctx_nodb, void(X509V3_CTX*));
    MOCK_METHOD1(SSL_X509_EXTENSION_free, void(X509_EXTENSION*));
    MOCK_METHOD3(SSL_X509_add_ext, int(X509*, X509_EXTENSION*, int));
    MOCK_METHOD4(SSL_X509V3_EXT_conf_nid, X509_EXTENSION*(lhash_st_CONF_VALUE*,
                                                          X509V3_CTX*,
                                                          int,
                                                          char*));
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

    MOCK_METHOD2(SSL_EVP_PKEY_CTX_new, EVP_PKEY_CTX*(EVP_PKEY*, ENGINE*));
    MOCK_METHOD2(SSL_EVP_PKEY_CTX_new_id, EVP_PKEY_CTX*(int, ENGINE*));
    MOCK_METHOD1(SSL_EVP_PKEY_CTX_free, void(EVP_PKEY_CTX*));
    MOCK_METHOD2(SSL_EVP_PKEY_CTX_set_rsa_keygen_bits, int(EVP_PKEY_CTX*, int));

    MOCK_METHOD2(SSL_EVP_PKEY_cmp, int(const EVP_PKEY*, const EVP_PKEY *));

    MOCK_METHOD1(SSL_EVP_PKEY_paramgen_init, int(EVP_PKEY_CTX*));
    MOCK_METHOD2(SSL_EVP_PKEY_paramgen, int(EVP_PKEY_CTX *ctx, EVP_PKEY **ppkey));
    MOCK_METHOD2(SSL_EVP_PKEY_CTX_set_ec_paramgen_curve_nid, int(EVP_PKEY_CTX *ctx, int nid));
    MOCK_METHOD2(SSL_EVP_PKEY_CTX_set_ec_param_enc, int(EVP_PKEY_CTX *ctx, int param_enc));
    MOCK_METHOD1(SSL_EC_KEY_get0_group, EC_GROUP*(const EC_KEY *key));
    MOCK_METHOD1(SSL_EC_GROUP_get_curve_name, int(const EC_GROUP *group));

    MOCK_METHOD1(SSL_EVP_PKEY_type, int(int type));
    MOCK_METHOD1(SSL_EVP_PKEY_size, int(EVP_PKEY *pkey));

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
    MOCK_METHOD0(SSL_EVP_sha1, const EVP_MD*());
    MOCK_METHOD0(SSL_EVP_sha256, const EVP_MD*());
    MOCK_METHOD0(SSL_EVP_sha384, const EVP_MD*());
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

    MOCK_METHOD2(SSL_PEM_write_bio_X509, int(BIO *bp, X509 *x));
    MOCK_METHOD2(SSL_d2i_X509_bio, X509*(BIO*, X509**));
    MOCK_METHOD2(SSL_i2d_X509_bio, int(BIO*, X509*));

    MOCK_METHOD0(SSL_X509_new, X509*());
    MOCK_METHOD2(SSL_X509_set_pubkey, int(X509* ptr, EVP_PKEY* pkey));
    MOCK_METHOD2(SSL_X509_set_issuer_name, int(X509 *x, X509_NAME *name));
    MOCK_METHOD2(SSL_X509_set_subject_name, int(X509 *x, X509_NAME *name));
    MOCK_METHOD2(SSL_X509_set_notBefore, int(X509 *x, const ASN1_TIME* t));
    MOCK_METHOD2(SSL_X509_set_notAfter, int(X509 *x, const ASN1_TIME* t));
    MOCK_METHOD3(SSL_X509_sign, int(X509 *x, EVP_PKEY *pkey, const EVP_MD *md));
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

    MOCK_METHOD1(SSL_X509_check_ca, int(X509*));

    MOCK_METHOD0(SSL_sk_X509_new_null, STACK_OF(X509)*());
    MOCK_METHOD2(SSL_sk_X509_push, int(STACK_OF(X509)*, const X509*));
    MOCK_METHOD1(SSL_sk_X509_free, void(STACK_OF(X509)*));

    MOCK_METHOD3(SSL_X509_NAME_get_index_by_NID, int(X509_NAME*, int, int));
    MOCK_METHOD2(SSL_X509_NAME_get_entry, X509_NAME_ENTRY*(X509_NAME*, int));
    MOCK_METHOD1(SSL_X509_NAME_ENTRY_get_data, ASN1_STRING*(X509_NAME_ENTRY*));
    MOCK_METHOD3(SSL_ASN1_STRING_print_ex, int(BIO*, ASN1_STRING*, unsigned long));

    MOCK_METHOD5(SSL_EVP_PKEY_sign, int(EVP_PKEY_CTX*, unsigned char*, size_t*, const unsigned char*, size_t));
    MOCK_METHOD1(SSL_EVP_PKEY_sign_init, int(EVP_PKEY_CTX*));
    MOCK_METHOD1(SSL_EVP_PKEY_verify_init, int(EVP_PKEY_CTX*));
    MOCK_METHOD5(SSL_EVP_PKEY_verify, int(EVP_PKEY_CTX*, const unsigned char*, size_t, const unsigned char*, size_t));
    MOCK_METHOD2(SSL_EVP_PKEY_CTX_set_rsa_padding, int(EVP_PKEY_CTX*, int));
    MOCK_METHOD2(SSL_EVP_PKEY_CTX_set_signature_md, int(EVP_PKEY_CTX*, const EVP_MD*));
    MOCK_METHOD2(SSL_EVP_PKEY_CTX_set_rsa_pss_saltlen, int(EVP_PKEY_CTX*, int));
    MOCK_METHOD2(SSL_EVP_PKEY_CTX_set_rsa_mgf1_md, int(EVP_PKEY_CTX*, const EVP_MD*));
    MOCK_METHOD1(SSL_EVP_PKEY_encrypt_init, int(EVP_PKEY_CTX *ctx));
    MOCK_METHOD5(SSL_EVP_PKEY_encrypt, int(EVP_PKEY_CTX *ctx,
                                           unsigned char *out, size_t *outlen,
                                           const unsigned char *in, size_t inlen));
    MOCK_METHOD1(SSL_EVP_PKEY_decrypt_init, int(EVP_PKEY_CTX *ctx));
    MOCK_METHOD5(SSL_EVP_PKEY_decrypt, int(EVP_PKEY_CTX *ctx,
                                           unsigned char *out, size_t *outlen,
                                           const unsigned char *in, size_t inlen));
    MOCK_METHOD2(SSL_EVP_PKEY_CTX_set_rsa_oaep_md, int(EVP_PKEY_CTX *ctx, const EVP_MD *md));
    MOCK_METHOD3(SSL_EVP_PKEY_CTX_set_rsa_oaep_label, int(EVP_PKEY_CTX *ctx, unsigned char *l,
                                                          int llen));
    MOCK_METHOD2(SSL_EVP_PKEY_CTX_get_rsa_oaep_label, int(EVP_PKEY_CTX *ctx, unsigned char *l));
    MOCK_METHOD1(SSL_RSA_size, int(const RSA *r));
    MOCK_METHOD1(SSL_EVP_MD_size, int(const EVP_MD *md));

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
    static ::testing::NiceMock<OpenSSLLibMock>& getMockInterface();

    /**
     * Reset the current OpenSSLLibMock instance
     * maintained within this class.
     */
    static void resetMock();

    /**
     * Destroy current mock object to trigger gmock call analysis
     */
    static void destroy();

private:
    static std::unique_ptr<::testing::NiceMock<OpenSSLLibMock>> _mock;

    /* Unsure how much parallization happens with regard to the tests
     * but let's be safe
     */
    static std::mutex _mutex;
};

}  // ::openssl
}  // ::mococrw
