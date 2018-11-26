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

/*
 * This file is the only place where we should see any
 * "vanilla" OpenSSL methods whatsoever. Any other
 * translation unit should use the methods exposed via
 * OpenSSLLib.
 *
 * Moreover, the methods exposed by OpenSSLLib should only
 * be used in openssl_wrap.cpp and openssl_wrap.h.
 *
 */

#include "mococrw/openssl_lib.h"

namespace mococrw
{
namespace openssl
{
/**
 * @brief Initializes OpenSSL once
 *
 * The methods here are needed to set up various openssl routines
 */
[[gnu::unused]] static bool initialized = [] {
    lib::OpenSSLLib::SSL_CRYPTO_malloc_init();
    lib::OpenSSLLib::SSL_ERR_load_crypto_strings();
    lib::OpenSSLLib::SSL_SSL_load_error_strings();
    lib::OpenSSLLib::SSL_OpenSSL_add_all_algorithms();
    return true;
}();
namespace lib
{
/* The implementation of OpenSSLLib class members.
 *
 *
 * Any method here simply forwards to an equivalent OpenSSL method
 */

void OpenSSLLib::SSL_CRYPTO_malloc_init() noexcept { CRYPTO_malloc_init(); }

void OpenSSLLib::SSL_ERR_load_crypto_strings() noexcept { ERR_load_crypto_strings(); }

void OpenSSLLib::SSL_SSL_load_error_strings() noexcept { SSL_load_error_strings(); }

void OpenSSLLib::SSL_OpenSSL_add_all_algorithms() noexcept { OpenSSL_add_all_algorithms(); }

void OpenSSLLib::SSL_X509_REQ_free(X509_REQ* ptr) noexcept { X509_REQ_free(ptr); }

X509_REQ* OpenSSLLib::SSL_X509_REQ_new() noexcept { return X509_REQ_new(); }

EVP_PKEY* OpenSSLLib::SSL_EVP_PKEY_new() noexcept { return EVP_PKEY_new(); }

void OpenSSLLib::SSL_EVP_PKEY_free(EVP_PKEY* ptr) noexcept { EVP_PKEY_free(ptr); }

int OpenSSLLib::SSL_EVP_PKEY_keygen(EVP_PKEY_CTX* ctx, EVP_PKEY** ppkey) noexcept
{
    return EVP_PKEY_keygen(ctx, ppkey);
}


int OpenSSLLib::SSL_EVP_PKEY_keygen_init(EVP_PKEY_CTX* ctx) noexcept
{
    return EVP_PKEY_keygen_init(ctx);
}

EVP_PKEY_CTX* OpenSSLLib::SSL_EVP_PKEY_CTX_new(EVP_PKEY *pkey, ENGINE* engine) noexcept
{
    return EVP_PKEY_CTX_new(pkey, engine);
}

EVP_PKEY_CTX* OpenSSLLib::SSL_EVP_PKEY_CTX_new_id(int id, ENGINE* engine) noexcept
{
    return EVP_PKEY_CTX_new_id(id, engine);
}


void OpenSSLLib::SSL_EVP_PKEY_CTX_free(EVP_PKEY_CTX* ptr) noexcept
{
    return EVP_PKEY_CTX_free(ptr);
}


int OpenSSLLib::SSL_EVP_PKEY_CTX_set_rsa_keygen_bits(EVP_PKEY_CTX* ctx, int mbits) noexcept
{
    return EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, mbits);
}

int OpenSSLLib::SSL_EVP_PKEY_cmp(const EVP_PKEY *a, const EVP_PKEY *b) noexcept
{
    return EVP_PKEY_cmp(a,b);
}

int OpenSSLLib::SSL_EVP_PKEY_paramgen_init(EVP_PKEY_CTX *ctx) noexcept
{
    return EVP_PKEY_paramgen_init(ctx);
}
int OpenSSLLib::SSL_EVP_PKEY_paramgen(EVP_PKEY_CTX *ctx, EVP_PKEY **ppkey) noexcept
{
    return EVP_PKEY_paramgen(ctx, ppkey);
}

int OpenSSLLib::SSL_EVP_PKEY_CTX_set_ec_paramgen_curve_nid(EVP_PKEY_CTX *ctx, int nid) noexcept
{
    return EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, nid);
}

int OpenSSLLib::SSL_EVP_PKEY_CTX_set_ec_param_enc(EVP_PKEY_CTX *ctx, int param_enc) noexcept
{
    return EVP_PKEY_CTX_set_ec_param_enc(ctx, param_enc);
}

const EC_GROUP* OpenSSLLib::SSL_EC_KEY_get0_group(const EC_KEY *key) noexcept
{
    return EC_KEY_get0_group(key);
}

int OpenSSLLib::SSL_EC_GROUP_get_curve_name(const EC_GROUP *group) noexcept
{
    return EC_GROUP_get_curve_name(group);
}

int OpenSSLLib::SSL_EVP_PKEY_type(int type) noexcept
{
    return EVP_PKEY_type(type);
}

int OpenSSLLib::SSL_EVP_PKEY_size(EVP_PKEY *pkey) noexcept
{
    return EVP_PKEY_size(pkey);
}

/* Reference counting magic */
int OpenSSLLib::SSL_CRYPTO_add(int *pointer, int amount, int type) noexcept {
    return CRYPTO_add(pointer, amount, type);
}

char* OpenSSLLib::SSL_ERR_error_string(unsigned long error, char* buf) noexcept
{
    return ERR_error_string(error, buf);
}

unsigned long OpenSSLLib::SSL_ERR_get_error() noexcept { return ERR_get_error(); }

X509_NAME* OpenSSLLib::SSL_X509_NAME_new() noexcept { return X509_NAME_new(); }

void OpenSSLLib::SSL_X509_NAME_free(X509_NAME* ptr) noexcept { X509_NAME_free(ptr); }

int OpenSSLLib::SSL_X509_NAME_add_entry_by_NID(X509_NAME* name,
                                               int nid,
                                               int type,
                                               unsigned char* bytes,
                                               int len,
                                               int loc,
                                               int set) noexcept
{
    return X509_NAME_add_entry_by_NID(name, nid, type, bytes, len, loc, set);
}

int OpenSSLLib::SSL_X509_REQ_set_subject_name(X509_REQ* req, X509_NAME* name) noexcept
{
    return X509_REQ_set_subject_name(req, name);
}

int OpenSSLLib::SSL_X509_REQ_set_pubkey(X509_REQ* req, EVP_PKEY* pkey) noexcept
{
    return X509_REQ_set_pubkey(req, pkey);
}

int OpenSSLLib::SSL_X509_REQ_set_version(X509_REQ* req, unsigned long version) noexcept
{
    return X509_REQ_set_version(req, version);
}

X509_NAME* OpenSSLLib::SSL_X509_REQ_get_subject_name(X509_REQ *req) noexcept
{
    return X509_REQ_get_subject_name(req);
}

EVP_PKEY* OpenSSLLib::SSL_X509_REQ_get_pubkey(X509_REQ *req) noexcept
{
    return X509_REQ_get_pubkey(req);
}

int OpenSSLLib::SSL_X509_REQ_verify(X509_REQ *req, EVP_PKEY *r) noexcept
{
    return X509_REQ_verify(req, r);
}

int OpenSSLLib::SSL_PEM_write_bio_X509_REQ(BIO* bio, X509_REQ* req) noexcept
{
    return PEM_write_bio_X509_REQ(bio, req);
}

X509_REQ* OpenSSLLib::SSL_PEM_read_bio_X509_REQ(BIO *bp,
                                          X509_REQ **x,
                                          pem_password_cb *cb,
                                          void *u) noexcept
{
    return PEM_read_bio_X509_REQ(bp, x, cb, u);
}

BIO_METHOD* OpenSSLLib::SSL_BIO_s_mem() noexcept { return BIO_s_mem(); }

void OpenSSLLib::SSL_BIO_free_all(BIO* ptr) noexcept { BIO_free_all(ptr); }

BIO* OpenSSLLib::SSL_BIO_new(BIO_METHOD* method) noexcept { return BIO_new(method); }

int OpenSSLLib::SSL_BIO_gets(BIO* bio, char* buf, int size) noexcept
{
    return BIO_gets(bio, buf, size);
}

int OpenSSLLib::SSL_X509_REQ_sign_ctx(X509_REQ* req, EVP_MD_CTX* ctx) noexcept
{
    return X509_REQ_sign_ctx(req, ctx);
}

EVP_MD_CTX* OpenSSLLib::SSL_EVP_MD_CTX_create() noexcept { return EVP_MD_CTX_create(); }

int OpenSSLLib::SSL_EVP_DigestSignInit(EVP_MD_CTX* ctx,
                                       EVP_PKEY_CTX** pctx,
                                       const EVP_MD* type,
                                       ENGINE* e,
                                       EVP_PKEY* pkey) noexcept
{
    return EVP_DigestSignInit(ctx, pctx, type, e, pkey);
}


void OpenSSLLib::SSL_EVP_MD_CTX_destroy(EVP_MD_CTX* ptr) noexcept { EVP_MD_CTX_destroy(ptr); }

const EVP_MD* OpenSSLLib::SSL_EVP_sha1() noexcept { return EVP_sha1(); }

const EVP_MD* OpenSSLLib::SSL_EVP_sha256() noexcept { return EVP_sha256(); }

const EVP_MD* OpenSSLLib::SSL_EVP_sha384() noexcept { return EVP_sha384(); }

const EVP_MD* OpenSSLLib::SSL_EVP_sha512() noexcept { return EVP_sha512(); }

const EVP_MD *OpenSSLLib::SSL_EVP_sha1() noexcept { return EVP_sha1(); }

int OpenSSLLib::SSL_PEM_write_bio_PKCS8PrivateKey(BIO *bp,
                                                  EVP_PKEY *x,
                                                  const EVP_CIPHER *enc,
                                                  char *kstr,
                                                  int klen,
                                                  pem_password_cb *cb,
                                                  void *u) noexcept
{
    return PEM_write_bio_PKCS8PrivateKey(bp, x, enc, kstr, klen, cb, u);
}

int OpenSSLLib::SSL_PEM_write_bio_PUBKEY(BIO* bp, EVP_PKEY* x) noexcept
{
    return PEM_write_bio_PUBKEY(bp, x);
}

EVP_PKEY* OpenSSLLib::SSL_PEM_read_bio_PUBKEY(BIO* bio,
                                              EVP_PKEY** pkey,
                                              pem_password_cb* cb,
                                              void* u) noexcept
{
    return PEM_read_bio_PUBKEY(bio, pkey, cb, u);
}


EVP_PKEY* OpenSSLLib::SSL_PEM_read_bio_PrivateKey(BIO* bio,
                                                  EVP_PKEY** pkey,
                                                  pem_password_cb* cb,
                                                  void* u) noexcept
{
    return PEM_read_bio_PrivateKey(bio, pkey, cb, u);
}

int OpenSSLLib::SSL_BIO_puts(BIO* bio, char* buf) noexcept { return BIO_puts(bio, buf); }

void OpenSSLLib::SSL_X509_free(X509* ptr) noexcept { X509_free(ptr); }

X509* OpenSSLLib::SSL_X509_new() noexcept { return X509_new(); }

int OpenSSLLib::SSL_X509_set_pubkey(X509* ptr, EVP_PKEY* pkey) noexcept
{
    return X509_set_pubkey(ptr, pkey);
}

int OpenSSLLib::SSL_X509_set_notBefore(X509 *x, const ASN1_TIME *t) noexcept
{
    return X509_set_notBefore(x, t);
}

int OpenSSLLib::SSL_X509_set_notAfter(X509 *x, const ASN1_TIME *t) noexcept
{
    return X509_set_notAfter(x, t);
}

int OpenSSLLib::SSL_X509_sign(X509 *x, EVP_PKEY *pkey, const EVP_MD *md) noexcept
{
    return X509_sign(x, pkey, md);
}

X509* OpenSSLLib::SSL_PEM_read_bio_X509(BIO *bio, X509 **x, pem_password_cb* cb, void* pwd) noexcept
{
    return PEM_read_bio_X509(bio, x, cb, pwd);
}

int OpenSSLLib::SSL_PEM_write_bio_X509(BIO *bp, X509 *x) noexcept
{
    return PEM_write_bio_X509(bp, x);
}

X509 *OpenSSLLib::SSL_d2i_X509_bio(BIO* bp, X509** x509) noexcept
{
    return d2i_X509_bio(bp, x509);
}

int OpenSSLLib::SSL_i2d_X509_bio(BIO* bp, X509* x) noexcept
{
    return i2d_X509_bio(bp, x);
}

/* X509 */
X509_NAME* OpenSSLLib::SSL_X509_get_subject_name(X509 *ptr) noexcept
{
    return X509_get_subject_name(ptr);
}

X509_NAME* OpenSSLLib::SSL_X509_get_issuer_name(X509 *ptr) noexcept
{
    return X509_get_issuer_name(ptr);
}

EVP_PKEY* OpenSSLLib::SSL_X509_get_pubkey(X509 *x) noexcept
{
    return X509_get_pubkey(x);
}

int OpenSSLLib::SSL_X509_set_subject_name(X509 *x, X509_NAME *name) noexcept
{
    return X509_set_subject_name(x, name);
}

int OpenSSLLib::SSL_X509_set_issuer_name(X509 *x, X509_NAME *name) noexcept
{
    return X509_set_issuer_name(x, name);
}

int OpenSSLLib::SSL_X509_NAME_get_index_by_NID(X509_NAME* name,
                                                        int nid,
                                                        int lastpos) noexcept
{
    return X509_NAME_get_index_by_NID(name, nid, lastpos);
}

X509_NAME_ENTRY* OpenSSLLib::SSL_X509_NAME_get_entry(X509_NAME* name, int loc) noexcept
{
    return X509_NAME_get_entry(name, loc);
}

ASN1_STRING * OpenSSLLib::SSL_X509_NAME_ENTRY_get_data(X509_NAME_ENTRY *ne) noexcept
{
    return X509_NAME_ENTRY_get_data(ne);
}

int OpenSSLLib::SSL_ASN1_STRING_print_ex(BIO *out, ASN1_STRING *str, unsigned long flags) noexcept
{
    return ASN1_STRING_print_ex(out, str, flags);
}

ASN1_TIME* OpenSSLLib::SSL_X509_get_notBefore(X509* x) noexcept
{
    return X509_get_notBefore(x);
}

ASN1_TIME* OpenSSLLib::SSL_X509_get_notAfter(X509* x) noexcept
{
    return X509_get_notAfter(x);
}

/* ASN1 TIME */
void OpenSSLLib::SSL_ASN1_TIME_free(ASN1_TIME *x) noexcept
{
    ASN1_TIME_free(x);
}

int OpenSSLLib::SSL_ASN1_TIME_diff(int *pday, int *psec,
                                   const ASN1_TIME *from, const ASN1_TIME *to) noexcept
{
    return ASN1_TIME_diff(pday, psec, from, to);
}

ASN1_TIME * OpenSSLLib::SSL_ASN1_TIME_set(ASN1_TIME *s, time_t t) noexcept
{
    return ASN1_TIME_set(s,t);
}

/* X509 Certificate validation */
X509_STORE* OpenSSLLib::SSL_X509_STORE_new() noexcept { return X509_STORE_new(); }

void OpenSSLLib::SSL_X509_STORE_free(X509_STORE *v) noexcept { X509_STORE_free(v); }

int OpenSSLLib::SSL_X509_STORE_add_cert(X509_STORE *ctx, X509 *x) noexcept
{
    return X509_STORE_add_cert(ctx,x);
}

X509_STORE_CTX* OpenSSLLib::SSL_X509_STORE_CTX_new() noexcept
{
    return X509_STORE_CTX_new();
}

void OpenSSLLib::SSL_X509_STORE_CTX_free(X509_STORE_CTX *ctx) noexcept
{
    X509_STORE_CTX_free(ctx);
}

int OpenSSLLib::SSL_X509_STORE_CTX_init(X509_STORE_CTX *ctx, X509_STORE *store, X509 *x509,
                                        STACK_OF(X509) *chain) noexcept
{
    return X509_STORE_CTX_init(ctx, store, x509, chain);
}

X509_VERIFY_PARAM* OpenSSLLib::SSL_X509_STORE_CTX_get0_param(X509_STORE_CTX *ctx) noexcept
{
    return X509_STORE_CTX_get0_param(ctx);
}

int OpenSSLLib::SSL_X509_VERIFY_PARAM_set_flags(X509_VERIFY_PARAM *param, unsigned long flags) noexcept
{
    return X509_VERIFY_PARAM_set_flags(param, flags);
}


int OpenSSLLib::SSL_X509_verify_cert(X509_STORE_CTX *ctx) noexcept
{
    return X509_verify_cert(ctx);
}

const char* OpenSSLLib::SSL_X509_verify_cert_error_string(long n) noexcept
{
    return X509_verify_cert_error_string(n);
}

int OpenSSLLib::SSL_X509_STORE_CTX_get_error(X509_STORE_CTX *ctx) noexcept
{
    return X509_STORE_CTX_get_error(ctx);
}

int OpenSSLLib::SSL_X509_check_ca(X509 *cert) noexcept
{
    return X509_check_ca(cert);
}

/* stack of X509 */
STACK_OF(X509)* OpenSSLLib::SSL_sk_X509_new_null() noexcept
{
    return sk_X509_new_null();
}

int OpenSSLLib::SSL_sk_X509_push(STACK_OF(X509)* stack, const X509 *crt) noexcept
{
    return sk_X509_push(stack, crt);
}
void OpenSSLLib::SSL_sk_X509_free(STACK_OF(X509)* stack) noexcept { sk_X509_free(stack); }

BIO* OpenSSLLib::SSL_BIO_new_file(const char* filename, const char* mode) noexcept
{
    return BIO_new_file(filename, mode);
}

int OpenSSLLib::SSL_BIO_read(BIO* b, void* buf, int len) noexcept
{
    return BIO_read(b, buf, len);
}

int OpenSSLLib::SSL_BIO_write(BIO* b, const void* buf, int len) noexcept
{
    return BIO_write(b, buf, len);
}

const EVP_CIPHER* OpenSSLLib::SSL_EVP_aes_256_cbc() noexcept
{
    return EVP_aes_256_cbc();
}

X509_EXTENSION* OpenSSLLib::SSL_X509V3_EXT_conf_nid(lhash_st_CONF_VALUE* conf,
                                                    X509V3_CTX* ctx,
                                                    int ext_nid,
                                                    char* value) noexcept
{
    return X509V3_EXT_conf_nid(conf, ctx, ext_nid, value);
}

int OpenSSLLib::SSL_X509_add_ext(X509* x, X509_EXTENSION* ex, int loc) noexcept
{
    return X509_add_ext(x, ex, loc);
}

void OpenSSLLib::SSL_X509_EXTENSION_free(X509_EXTENSION* a) noexcept
{
    X509_EXTENSION_free(a);
}

void OpenSSLLib::SSL_X509V3_set_ctx_nodb(X509V3_CTX* ctx) noexcept
{
    X509V3_set_ctx_nodb(ctx);
}
void OpenSSLLib::SSL_X509V3_set_ctx(X509V3_CTX* ctx,
                                    X509* issuer,
                                    X509* subject,
                                    X509_REQ* req,
                                    X509_CRL* crl,
                                    int flags) noexcept
{
    X509V3_set_ctx(ctx, issuer, subject, req, crl, flags);
}
int OpenSSLLib::SSL_X509_set_serialNumber(X509* x, ASN1_INTEGER* serial) noexcept
{
    return X509_set_serialNumber(x, serial);
}
ASN1_INTEGER* OpenSSLLib::SSL_X509_get_serialNumber(X509* x) noexcept
{
    return X509_get_serialNumber(x);
}
int OpenSSLLib::SSL_ASN1_INTEGER_set(ASN1_INTEGER* a, long value) noexcept
{
    return ASN1_INTEGER_set(a, value);
}
long OpenSSLLib::SSL_ASN1_INTEGER_get(const ASN1_INTEGER* a) noexcept
{
    return ASN1_INTEGER_get(a);
}
int OpenSSLLib::SSL_ASN1_INTEGER_cmp(const ASN1_INTEGER* x, const ASN1_INTEGER* y) noexcept
{
    return ASN1_INTEGER_cmp(x, y);
}
BIGNUM* OpenSSLLib::SSL_ASN1_INTEGER_to_BN(const ASN1_INTEGER* ai, BIGNUM* bn) noexcept
{
    return ASN1_INTEGER_to_BN(ai, bn);
}
void OpenSSLLib::SSL_BN_free(BIGNUM* a) noexcept
{
    BN_free(a);
}
char* OpenSSLLib::SSL_BN_bn2dec(const BIGNUM* a) noexcept
{
    return BN_bn2dec(a);
}
void* OpenSSLLib::SSL_OPENSSL_malloc(int num) noexcept
{
    return OPENSSL_malloc(num);
}
void OpenSSLLib::SSL_OPENSSL_free(void* addr) noexcept
{
    OPENSSL_free(addr);
}
void OpenSSLLib::SSL_ASN1_INTEGER_free(ASN1_INTEGER* a) noexcept
{
    ASN1_INTEGER_free(a);
}
ASN1_INTEGER* OpenSSLLib::SSL_ASN1_INTEGER_new() noexcept
{
    return ASN1_INTEGER_new();
}
int OpenSSLLib::SSL_BN_bn2bin(const BIGNUM* a, unsigned char* to) noexcept
{
    return BN_bn2bin(a, to);
}
int OpenSSLLib::SSL_BN_num_bytes(const BIGNUM* a) noexcept
{
    return BN_num_bytes(a);
}
int OpenSSLLib::SSL_ASN1_TIME_set_string(ASN1_TIME* s, const char* str) noexcept
{
    return ASN1_TIME_set_string(s, str);
}
ASN1_TIME* OpenSSLLib::SSL_ASN1_TIME_new() noexcept
{
    return ASN1_TIME_new();
}
ASN1_STRING* OpenSSLLib::SSL_ASN1_STRING_dup(const ASN1_STRING* str) noexcept
{
    return ASN1_STRING_dup(str);
}
X509_NAME* OpenSSLLib::SSL_X509_CRL_get_issuer(const X509_CRL* crl) noexcept
{
    return X509_CRL_get_issuer(crl);
}
int OpenSSLLib::SSL_X509_CRL_verify(X509_CRL* a, EVP_PKEY* r) noexcept
{
    return X509_CRL_verify(a, r);
}
ASN1_TIME* OpenSSLLib::SSL_X509_CRL_get_nextUpdate(const X509_CRL* x) noexcept
{
    return X509_CRL_get_nextUpdate(x);
}
ASN1_TIME* OpenSSLLib::SSL_X509_CRL_get_lastUpdate(const X509_CRL* x) noexcept
{
    return X509_CRL_get_lastUpdate(x);
}
X509_CRL* OpenSSLLib::SSL_PEM_read_bio_X509_CRL(BIO* bp, X509_CRL** x, pem_password_cb* cb, void* u) noexcept
{
    return PEM_read_bio_X509_CRL(bp, x, cb, u);
}
int OpenSSLLib::SSL_PEM_write_bio_X509_CRL(BIO* bp, X509_CRL* x) noexcept
{
    return PEM_write_bio_X509_CRL(bp, x);
}
X509_CRL* OpenSSLLib::SSL_d2i_X509_CRL_bio(BIO* bp, X509_CRL** crl) noexcept
{
    return d2i_X509_CRL_bio(bp, crl);
}
void OpenSSLLib::SSL_X509_CRL_free(X509_CRL* a) noexcept
{
    X509_CRL_free(a);
}
X509_CRL* OpenSSLLib::SSL_X509_CRL_new() noexcept
{
    return X509_CRL_new();
}
void OpenSSLLib::SSL_X509_STORE_CTX_set0_crls(X509_STORE_CTX* ctx, STACK_OF(X509_CRL)* crls) noexcept
{
    X509_STORE_CTX_set0_crls(ctx, crls);
}
void OpenSSLLib::SSL_sk_X509_CRL_free(STACK_OF(X509_CRL)* stack) noexcept
{
    sk_X509_CRL_free(stack);
}
STACK_OF(X509_CRL)* OpenSSLLib::SSL_sk_X509_CRL_new_null() noexcept
{
    return sk_X509_CRL_new_null();
}
int OpenSSLLib::SSL_sk_X509_CRL_push(STACK_OF(X509_CRL)* stack, const X509_CRL* crl) noexcept
{
    return sk_X509_CRL_push(stack, crl);
}
ASN1_TIME* OpenSSLLib::SSL_ASN1_TIME_adj(ASN1_TIME* s, time_t t, int offset_day, long offset_sec) noexcept
{
    return ASN1_TIME_adj(s, t, offset_day, offset_sec);
}
void OpenSSLLib::SSL_X509_STORE_CTX_set_time(X509_STORE_CTX* ctx, unsigned long flags, time_t t) noexcept
{
    X509_STORE_CTX_set_time(ctx, flags, t);
}
void OpenSSLLib::SSL_EVP_MD_CTX_init(EVP_MD_CTX* ctx) noexcept
{
    EVP_MD_CTX_init(ctx);
}
int OpenSSLLib::SSL_EVP_DigestInit_ex(EVP_MD_CTX* ctx, const EVP_MD* type, ENGINE* impl) noexcept
{
    return EVP_DigestInit_ex(ctx, type, impl);
}
int OpenSSLLib::SSL_EVP_DigestUpdate(EVP_MD_CTX* ctx, const void* d, size_t cnt) noexcept
{
    return EVP_DigestUpdate(ctx, d, cnt);
}
int OpenSSLLib::SSL_EVP_DigestFinal_ex(EVP_MD_CTX* ctx, unsigned char* md, unsigned int* s) noexcept
{
    return EVP_DigestFinal_ex(ctx, md, s);
}
int OpenSSLLib::SSL_EVP_MD_CTX_cleanup(EVP_MD_CTX* ctx) noexcept
{
    return EVP_MD_CTX_cleanup(ctx);
}
int OpenSSLLib::SSL_EVP_PKEY_encrypt_init(EVP_PKEY_CTX *ctx) noexcept
{
    return EVP_PKEY_encrypt_init(ctx);
}
int OpenSSLLib::SSL_EVP_PKEY_encrypt(EVP_PKEY_CTX *ctx,
                                     unsigned char *out, size_t *outlen,
                                     const unsigned char *in, size_t inlen) noexcept
{
    return EVP_PKEY_encrypt(ctx, out, outlen, in, inlen);
}
int OpenSSLLib::SSL_EVP_PKEY_decrypt_init(EVP_PKEY_CTX *ctx) noexcept
{
    return EVP_PKEY_decrypt_init(ctx);
}
int OpenSSLLib::SSL_EVP_PKEY_decrypt(EVP_PKEY_CTX *ctx,
                                     unsigned char *out, size_t *outlen,
                                     const unsigned char *in, size_t inlen) noexcept
{
    return EVP_PKEY_decrypt(ctx, out, outlen, in, inlen);
}
int OpenSSLLib::SSL_EVP_PKEY_CTX_set_rsa_oaep_md(EVP_PKEY_CTX *ctx, const EVP_MD *md) noexcept
{
    return EVP_PKEY_CTX_set_rsa_oaep_md(ctx, md);
}
int OpenSSLLib::SSL_EVP_PKEY_CTX_set_rsa_oaep_label(EVP_PKEY_CTX *ctx, unsigned char *l, int llen) noexcept
{
    return EVP_PKEY_CTX_set0_rsa_oaep_label(ctx, l, llen);
}
int OpenSSLLib::SSL_EVP_PKEY_CTX_get_rsa_oaep_label(EVP_PKEY_CTX *ctx, unsigned char *l) noexcept
{
    return EVP_PKEY_CTX_get0_rsa_oaep_label(ctx, l);
}
int OpenSSLLib::SSL_RSA_size(const RSA *r) noexcept
{
    return RSA_size(r);
}
int OpenSSLLib::SSL_EVP_MD_size(const EVP_MD *md) noexcept
{
    return EVP_MD_size(md);
}

/* Signatures */
int OpenSSLLib::SSL_EVP_PKEY_sign(EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen, const unsigned char *tbs, size_t tbslen) noexcept
{
    return EVP_PKEY_sign(ctx, sig, siglen, tbs, tbslen);
}
int OpenSSLLib::SSL_EVP_PKEY_sign_init(EVP_PKEY_CTX *ctx) noexcept
{
    return EVP_PKEY_sign_init(ctx);
}

int OpenSSLLib::SSL_EVP_PKEY_verify_init(EVP_PKEY_CTX *ctx) noexcept
{
    return EVP_PKEY_verify_init(ctx);
}

int OpenSSLLib::SSL_EVP_PKEY_verify(EVP_PKEY_CTX *ctx,
                           const unsigned char *sig, size_t siglen,
                           const unsigned char *tbs, size_t tbslen) noexcept
{
    return EVP_PKEY_verify(ctx, sig, siglen, tbs, tbslen);
}

int OpenSSLLib::SSL_EVP_PKEY_CTX_set_rsa_padding(EVP_PKEY_CTX *ctx, int pad) noexcept
{
    return EVP_PKEY_CTX_set_rsa_padding(ctx, pad);
}
int OpenSSLLib::SSL_EVP_PKEY_CTX_set_signature_md(EVP_PKEY_CTX *ctx, const EVP_MD* md) noexcept
{
    return EVP_PKEY_CTX_set_signature_md(ctx, md);
}

int OpenSSLLib::SSL_EVP_PKEY_CTX_set_rsa_pss_saltlen(EVP_PKEY_CTX *ctx, int len) noexcept
{
    return EVP_PKEY_CTX_set_rsa_pss_saltlen(ctx, len);
}
int OpenSSLLib::SSL_EVP_PKEY_CTX_set_rsa_mgf1_md(EVP_PKEY_CTX *ctx, const EVP_MD *md) noexcept
{
    return EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, md);
}
}  //::lib
}  //::openssl
}  //::mococrw
