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
 * methods from OpenSSLLib. Any other code should use
 * the more high-level methods declared and define in
 * openssl_wrap.cpp and openssl_wrap.h.
 *
 */

#include <cstddef> /* this has to come before cppc (bug in boost) */
#include <exception>
#include <limits>

#include <cppc/checkcall.hpp>

#include "mococrw/bio.h"
#include "mococrw/openssl_wrap.h"

using namespace std::chrono_literals;

namespace mococrw
{
namespace openssl
{
std::string OpenSSLException::generateOpenSSLErrorString()
{
    auto error = lib::OpenSSLLib::SSL_ERR_get_error();
    auto formatter = boost::format("%s: %d");
    formatter % lib::OpenSSLLib::SSL_ERR_error_string(error, nullptr) % error;
    return formatter.str();
}

/**
 * This struct is used by CWrap to
 * determine how to react to an error
 * when performing an openssl-call.
 */
struct OpenSSLExceptionErrorPolicy
{
    template <class Rv>
    static void handleError(const Rv&);
};

/**
 * Throw an OpenSSLException on error.
 *
 * This method gets the error string and throws an exception
 * with the corresponding message.
 */
template <class Rv>
void OpenSSLExceptionErrorPolicy::handleError(const Rv& /* unused */)
{
    throw OpenSSLException();
}

/**
 * OpenSSL returns 1 for success and anything other than
 * that indicates some kind of error.
 */
struct OpenSSLIsOneReturnCheckPolicy
{
    template <class Rv>
    static inline bool returnValueIsOk(const Rv& rv)
    {
        return rv == 1;
    }
};

/**
 * Some OpenSSL functions return positive values for success
 * and zero or negative values to indicate some failure.
 */
struct OpenSSLPositiveReturnCheckPolicy
{
    template <class Rv>
    static inline bool returnValueIsOk(const Rv &rv)
    {
        return rv > 0;
    }
};

/**
 * Some OpenSSL functions return positive values or zero for success
 * and negative values to indicate some failure.
 */
struct OpenSSLNonNegativeReturnCheckPolicy
{
    template <class Rv>
    static inline bool returnValueIsOk(const Rv &rv)
    {
        return rv >= 0;
    }
};


/**
 * CPPC provides a template-class 'CallCheckContext' that
 * as a method 'callChecked'. This method can be called like
 * so callChecked(<somemthodname>, <parameters>...) and will
 * then inspect the return-value according to a ReturnCheckPolicy,
 * and handle error according to an ErrorPolicy.
 *
 * Our policies are defined above. We now set up aliases for the
 * instantiated template.
 */
using OpensslCallIsOne =
        ::cppc::CallCheckContext<OpenSSLIsOneReturnCheckPolicy, OpenSSLExceptionErrorPolicy>;
using OpensslCallIsNonNegative =
        ::cppc::CallCheckContext<OpenSSLNonNegativeReturnCheckPolicy, OpenSSLExceptionErrorPolicy>;
using OpensslCallIsPositive =
        ::cppc::CallCheckContext<OpenSSLPositiveReturnCheckPolicy, OpenSSLExceptionErrorPolicy>;
using OpensslCallPtr = ::cppc::CallCheckContext<::cppc::IsNotNullptrReturnCheckPolicy,
                                                OpenSSLExceptionErrorPolicy>;

SSL_EVP_PKEY_Ptr _EVP_PKEY_new()
{
    return SSL_EVP_PKEY_Ptr{OpensslCallPtr::callChecked(lib::OpenSSLLib::SSL_EVP_PKEY_new)};
}

SSL_X509_REQ_Ptr _X509_REQ_new()
{
    return SSL_X509_REQ_Ptr{OpensslCallPtr::callChecked(lib::OpenSSLLib::SSL_X509_REQ_new)};
}

void _EVP_DigestFinal_ex(EVP_MD_CTX* ctx, unsigned char* md, unsigned int* s) {
    OpensslCallIsOne::callChecked(lib::OpenSSLLib::SSL_EVP_DigestFinal_ex, ctx, md, s);
}

void _EVP_DigestUpdate(EVP_MD_CTX* ctx, const void* d, size_t cnt) {
    OpensslCallIsOne::callChecked(lib::OpenSSLLib::SSL_EVP_DigestUpdate, ctx, d, cnt);
}

void _EVP_DigestInit_ex(EVP_MD_CTX* ctx, const EVP_MD* type, ENGINE* impl) {
    OpensslCallIsOne::callChecked(lib::OpenSSLLib::SSL_EVP_DigestInit_ex, ctx, type, impl);
}

void _EVP_MD_CTX_init(EVP_MD_CTX* ctx) {
    lib::OpenSSLLib::SSL_EVP_MD_CTX_init(ctx);
}

/**
 * The ENGINE parameter is currently unused, which is why we have not wrapped this data-type (yet).
 *
 */
SSL_EVP_PKEY_CTX_Ptr _EVP_PKEY_CTX_new(EVP_PKEY *pkey)
{
    return SSL_EVP_PKEY_CTX_Ptr{
            OpensslCallPtr::callChecked(lib::OpenSSLLib::SSL_EVP_PKEY_CTX_new, pkey, nullptr)};
}

/**
 * The ENGINE parameter is currently unused, which is why we have not wrapped this data-type (yet).
 *
 */
SSL_EVP_PKEY_CTX_Ptr _EVP_PKEY_CTX_new_id(int id)
{
    return SSL_EVP_PKEY_CTX_Ptr{
            OpensslCallPtr::callChecked(lib::OpenSSLLib::SSL_EVP_PKEY_CTX_new_id, id, nullptr)};
}

SSL_EVP_PKEY_Ptr _EVP_PKEY_keygen(EVP_PKEY_CTX* ctx)
{
    EVP_PKEY* ptr{nullptr};
    try {
        OpensslCallIsOne::callChecked(lib::OpenSSLLib::SSL_EVP_PKEY_keygen, ctx, &ptr);
    } catch (const OpenSSLException& e) {
        if (ptr) {
            lib::OpenSSLLib::SSL_EVP_PKEY_free(ptr);
        }

        throw e;
    }

    return SSL_EVP_PKEY_Ptr{ptr};
}

void _EVP_PKEY_keygen_init(EVP_PKEY_CTX* ctx)
{
    OpensslCallIsOne::callChecked(lib::OpenSSLLib::SSL_EVP_PKEY_keygen_init, ctx);
}

void _EVP_PKEY_CTX_set_rsa_keygen_bits(EVP_PKEY_CTX* ctx, int mbits)
{
    OpensslCallIsOne::callChecked(lib::OpenSSLLib::SSL_EVP_PKEY_CTX_set_rsa_keygen_bits, ctx, mbits);
}

void _EVP_PKEY_paramgen_init(EVP_PKEY_CTX *ctx)
{
    OpensslCallIsOne::callChecked(lib::OpenSSLLib::SSL_EVP_PKEY_paramgen_init, ctx);
}

SSL_EVP_PKEY_Ptr _EVP_PKEY_paramgen(EVP_PKEY_CTX *ctx)
{
    EVP_PKEY* ptr{nullptr};
    OpensslCallIsOne::callChecked(lib::OpenSSLLib::SSL_EVP_PKEY_paramgen, ctx, &ptr);
    return SSL_EVP_PKEY_Ptr{ptr};
}

void _EVP_PKEY_CTX_set_ec_paramgen_curve_nid(EVP_PKEY_CTX *ctx, int nid)
{
    OpensslCallIsNonNegative::callChecked(lib::OpenSSLLib::SSL_EVP_PKEY_CTX_set_ec_paramgen_curve_nid,
                                          ctx, nid);
}

void _EVP_PKEY_CTX_set_ec_param_enc(EVP_PKEY_CTX *ctx, int param_enc)
{
    OpensslCallIsNonNegative::callChecked(lib::OpenSSLLib::SSL_EVP_PKEY_CTX_set_ec_param_enc,
                                          ctx, param_enc);
}

const EC_GROUP* _EC_KEY_get0_group(const EC_KEY *key)
{
    return OpensslCallPtr::callChecked(lib::OpenSSLLib::SSL_EC_KEY_get0_group, key);
}

int _EC_GROUP_get_curve_name(const EC_GROUP *group)
{
    return OpensslCallIsPositive::callChecked(lib::OpenSSLLib::SSL_EC_GROUP_get_curve_name, group);
}

int _EVP_PKEY_type(const EVP_PKEY* key)
{
    return OpensslCallIsPositive::callChecked(lib::OpenSSLLib::SSL_EVP_PKEY_type, key->type);
}

int _EVP_PKEY_size(EVP_PKEY *pkey)
{
    return OpensslCallIsPositive::callChecked(lib::OpenSSLLib::SSL_EVP_PKEY_size, pkey);
}

bool _EVP_PKEY_cmp(const EVP_PKEY *a, const EVP_PKEY *b)
{
    int result = lib::OpenSSLLib::SSL_EVP_PKEY_cmp(a,b);
    if (result == 1) {
        return true;
    } else if (result == 0 || result == -1) {
        // OpenSSL returns 0 if the parameters don't match and -1 if the key types are different
        return false;
    } else {
        // there was an error, OpenSSL indicates that the operation may not be supported
        throw OpenSSLException();
    }
}

int _CRYPTO_add(int *pointer, int amount, int type) {
    return lib::OpenSSLLib::SSL_CRYPTO_add(pointer, amount, type);
}

SSL_X509_NAME_Ptr _X509_NAME_new()
{
    return SSL_X509_NAME_Ptr{OpensslCallPtr::callChecked(lib::OpenSSLLib::SSL_X509_NAME_new)};
}

void _X509_NAME_add_entry_by_NID(X509_NAME* name,
                                 ASN1_NID nid,
                                 ASN1_Name_Entry_Type type,
                                 std::vector<unsigned char>& bytes)
{
    OpensslCallIsOne::callChecked(lib::OpenSSLLib::SSL_X509_NAME_add_entry_by_NID,
                                name,
                                static_cast<int>(nid),
                                static_cast<int>(type),
                                bytes.data(),
                                bytes.size(),
                                -1, /* append at the end */
                                0); /* add a new RDN (see 'man X509_NAME_add_entry_by_txt') */
}

void _X509_REQ_set_subject_name(X509_REQ* req, X509_NAME* name)
{
    OpensslCallIsOne::callChecked(lib::OpenSSLLib::SSL_X509_REQ_set_subject_name, req, name);
}

void _X509_REQ_set_pubkey(X509_REQ* req, EVP_PKEY* pkey)
{
    OpensslCallIsOne::callChecked(lib::OpenSSLLib::SSL_X509_REQ_set_pubkey, req, pkey);
}

void _X509_REQ_set_version(X509_REQ* req, unsigned long version)
{
    OpensslCallIsOne::callChecked(lib::OpenSSLLib::SSL_X509_REQ_set_version, req, version);
}

X509_NAME* _X509_REQ_get_subject_name(X509_REQ *req)
{
    return OpensslCallPtr::callChecked(lib::OpenSSLLib::SSL_X509_REQ_get_subject_name, req);
}

SSL_EVP_PKEY_Ptr _X509_REQ_get_public_key(X509_REQ *req)
{
    return SSL_EVP_PKEY_Ptr{
        OpensslCallPtr::callChecked(lib::OpenSSLLib::SSL_X509_REQ_get_pubkey, req)};
}

void _X509_REQ_verify(X509_REQ *req, EVP_PKEY *key)
{
    OpensslCallIsOne::callChecked(lib::OpenSSLLib::SSL_X509_REQ_verify, req, key);
}

void _PEM_write_bio_X509_REQ(BIO* bio, X509_REQ* req)
{
    OpensslCallIsOne::callChecked(lib::OpenSSLLib::SSL_PEM_write_bio_X509_REQ, bio, req);
}

void _PEM_write_bio_X509(BIO* bio, X509* x)
{
    OpensslCallIsOne::callChecked(lib::OpenSSLLib::SSL_PEM_write_bio_X509, bio, x);
}

SSL_X509_REQ_Ptr _PEM_read_bio_X509_REQ(BIO* bio)
{
    return SSL_X509_REQ_Ptr{OpensslCallPtr::callChecked(lib::OpenSSLLib::SSL_PEM_read_bio_X509_REQ,
                                          bio, // the bio object to read from
                                          nullptr, //we do not pass in an "out-argument pointer"
                                          nullptr, // no callback for a password
                                          nullptr)}; // no password either
}

BIO_METHOD* _BIO_s_mem() { return lib::OpenSSLLib::SSL_BIO_s_mem(); }

SSL_BIO_Ptr _BIO_new(BIO_METHOD* method)
{
    return SSL_BIO_Ptr{OpensslCallPtr::callChecked(lib::OpenSSLLib::SSL_BIO_new, method)};
}

SSL_BIO_Ptr _BIO_new_file(const char *filename, const char *mode)
{
    return SSL_BIO_Ptr{OpensslCallPtr::callChecked(lib::OpenSSLLib::SSL_BIO_new_file, filename, mode)};
}

int _BIO_gets(BIO* bio, std::vector<char>& buf)
{
    int rv = lib::OpenSSLLib::SSL_BIO_gets(bio, buf.data(), buf.size());
    if (rv == -2) {
        throw OpenSSLException("Method 'gets' not implemented for this BIO");
    }
    return rv;
}


int _BIO_puts(BIO* bio, std::string buf)
{
    int rv = lib::OpenSSLLib::SSL_BIO_puts(bio, const_cast<char*>(buf.c_str()));
    if (rv == -2) {
        throw OpenSSLException("Method 'puts' not implemented for this BIO");
    }
    return rv;
}

int _BIO_write(BIO* bio, const std::vector<uint8_t> &data)
{
    if (data.size() > std::numeric_limits<int>::max()) {
        throw OpenSSLException("BIO_write cannot be called with so much data");
    }

    int rv = lib::OpenSSLLib::SSL_BIO_write(bio, data.data(), static_cast<int>(data.size()));
    if (rv == -2) {
        throw OpenSSLException("Method 'write' not implemented for this BIO");
    }
    return rv;
}

int _BIO_read(BIO* bio, std::vector<uint8_t> &buf, std::size_t numBytes)
{
    if (numBytes > std::numeric_limits<int>::max()) {
        throw OpenSSLException("BIO_read cannot be called with so much data");
    }
    buf.resize(numBytes);

    int rv = lib::OpenSSLLib::SSL_BIO_read(bio, buf.data(), static_cast<int>(numBytes));
    if (rv == -2) {
        throw OpenSSLException("Method 'read' not implemented for this BIO");
    } else if (rv > 0) {
        buf.resize(rv);
    } else {
        buf.resize(0);
    }
    return rv;

}


SSL_X509_Ptr _d2i_X509_bio(BIO* bp)
{
    return SSL_X509_Ptr{OpensslCallPtr::callChecked(lib::OpenSSLLib::SSL_d2i_X509_bio, bp, nullptr)};
}


void _i2d_X509_bio(BIO* bp, X509* x)
{
    OpensslCallIsOne::callChecked(lib::OpenSSLLib::SSL_i2d_X509_bio, bp, x);
}


void _X509_REQ_sign_ctx(X509_REQ* req, EVP_MD_CTX* ctx)
{
    OpensslCallIsPositive::callChecked(lib::OpenSSLLib::SSL_X509_REQ_sign_ctx, req, ctx);
}

const EVP_MD* _getMDPtrFromDigestType(DigestTypes type)
{
    switch (type) {
        case DigestTypes::SHA1:
            return lib::OpenSSLLib::SSL_EVP_sha1();
        case DigestTypes::SHA256:
            return lib::OpenSSLLib::SSL_EVP_sha256();
        case DigestTypes::SHA384:
            return lib::OpenSSLLib::SSL_EVP_sha384();
        case DigestTypes::SHA512:
            return lib::OpenSSLLib::SSL_EVP_sha512();
        default:
            throw std::runtime_error("Unknown digest type");
    }
}

void _EVP_DigestSignInit(EVP_MD_CTX* ctx, DigestTypes type, EVP_PKEY* pkey)
{
    const EVP_MD* md = _getMDPtrFromDigestType(type);
    OpensslCallIsOne::callChecked(lib::OpenSSLLib::SSL_EVP_DigestSignInit,
                                ctx,
                                nullptr,  // We do not need to change the parameters of the hash
                                md,
                                nullptr,  // We do not specify an engine
                                pkey);
}

SSL_EVP_MD_CTX_Ptr _EVP_MD_CTX_create()
{
    return SSL_EVP_MD_CTX_Ptr{OpensslCallPtr::callChecked(lib::OpenSSLLib::SSL_EVP_MD_CTX_create)};
}

void _PEM_write_bio_PKCS8PrivateKey(BIO* out, EVP_PKEY* pkey, const EVP_CIPHER* cipher,
                                    std::string pwd)
{
    OpensslCallIsOne::callChecked(lib::OpenSSLLib::SSL_PEM_write_bio_PKCS8PrivateKey,
                                out,
                                pkey,
                                cipher,
                                /* yes, it's ugly but OpenSSL expect a pointer to unsigned char
                                 * that is pointing to non-const */
                                const_cast<char*>(pwd.c_str()),
                                pwd.size(),
                                nullptr,
                                nullptr);
}

void _PEM_write_bio_PUBKEY(BIO* bp, EVP_PKEY* x)

{
    OpensslCallIsOne::callChecked(lib::OpenSSLLib::SSL_PEM_write_bio_PUBKEY, bp, x);
}

SSL_EVP_PKEY_Ptr _PEM_read_bio_PrivateKey(BIO* bio, std::string pwd)
{
    return SSL_EVP_PKEY_Ptr{
            OpensslCallPtr::callChecked(lib::OpenSSLLib::SSL_PEM_read_bio_PrivateKey,
                                        bio,
                                        nullptr,
                                        nullptr,
                                        const_cast<char*>(pwd.c_str()))};
}

SSL_EVP_PKEY_Ptr _PEM_read_bio_PUBKEY(BIO* bio)
{
    return SSL_EVP_PKEY_Ptr{OpensslCallPtr::callChecked(
            lib::OpenSSLLib::SSL_PEM_read_bio_PUBKEY, bio, nullptr, nullptr, nullptr)};
}

SSL_X509_Ptr _PEM_read_bio_X509(BIO *bio)
{
    return SSL_X509_Ptr{ OpensslCallPtr::callChecked(lib::OpenSSLLib::SSL_PEM_read_bio_X509,
                                        bio, // the bio object to read from
                                        nullptr, //we do not pass in an "out-argument pointer"
                                        nullptr, // no callback for a password
                                        nullptr)}; // no password either
}

void _X509_STORE_add_cert(X509_STORE *store, X509 *cert)
{
    OpensslCallIsOne::callChecked(lib::OpenSSLLib::SSL_X509_STORE_add_cert, store, cert);
}

void _X509_STORE_CTX_init(X509_STORE_CTX *ctx, X509_STORE *store, X509 *x509, STACK_OF(X509) *chain)
{
    OpensslCallIsOne::callChecked(lib::OpenSSLLib::SSL_X509_STORE_CTX_init, ctx, store, x509, chain);
}

X509_VERIFY_PARAM* _X509_STORE_CTX_get0_param(X509_STORE_CTX *ctx) {
    return OpensslCallPtr::callChecked(lib::OpenSSLLib::SSL_X509_STORE_CTX_get0_param, ctx);
}

bool _X509_check_ca(X509 *cert) {
    return lib::OpenSSLLib::SSL_X509_check_ca(cert);
}

void _X509_VERIFY_PARAM_set_flags(X509_VERIFY_PARAM *param, unsigned long flags) {
    OpensslCallIsOne::callChecked(lib::OpenSSLLib::SSL_X509_VERIFY_PARAM_set_flags, param, flags);
}

void _X509_verify_cert(X509_STORE_CTX *ctx) {
    // we don't use checkedCall here because the error message handling is special
    // in this method...
    auto result = lib::OpenSSLLib::SSL_X509_verify_cert(ctx);
    if (result != 1) {
        throw OpenSSLException(
            lib::OpenSSLLib::SSL_X509_verify_cert_error_string(
                lib::OpenSSLLib::SSL_X509_STORE_CTX_get_error(ctx)
            ));
    }
}

template<>
ASN1_INTEGER *createOpenSSLObject<ASN1_INTEGER>()
{
    return OpensslCallPtr::callChecked(lib::OpenSSLLib::SSL_ASN1_INTEGER_new);
}

template<>
X509_STORE *createOpenSSLObject<X509_STORE>()
{
    return OpensslCallPtr::callChecked(lib::OpenSSLLib::SSL_X509_STORE_new);
}

template<>
STACK_OF(X509_CRL) *createOpenSSLObject<STACK_OF(X509_CRL)>()
{
    return OpensslCallPtr::callChecked(lib::OpenSSLLib::SSL_sk_X509_CRL_new_null);
}

template<>
X509_STORE_CTX *createOpenSSLObject<X509_STORE_CTX>()
{
    return OpensslCallPtr::callChecked(lib::OpenSSLLib::SSL_X509_STORE_CTX_new);
}

template<>
STACK_OF(X509) *createOpenSSLObject<STACK_OF(X509)>()
{
    return OpensslCallPtr::callChecked(lib::OpenSSLLib::SSL_sk_X509_new_null);
}

template<>
X509 *createOpenSSLObject<X509>()
{
    return OpensslCallPtr::callChecked(lib::OpenSSLLib::SSL_X509_new);
}

template<>
X509_CRL *createOpenSSLObject<X509_CRL>()
{
    return OpensslCallPtr::callChecked(lib::OpenSSLLib::SSL_X509_CRL_new);
}

template<>
void addObjectToStack<STACK_OF(X509), X509>(STACK_OF(X509) *stack, const X509 *obj)
{
    OpensslCallIsPositive::callChecked(lib::OpenSSLLib::SSL_sk_X509_push, stack, obj);
}

template<>
void addObjectToStack<STACK_OF(X509_CRL), X509_CRL>(STACK_OF(X509_CRL) *stack, const X509_CRL *obj)
{
    OpensslCallIsPositive::callChecked(lib::OpenSSLLib::SSL_sk_X509_CRL_push, stack, obj);
}

X509_NAME* _X509_get_subject_name(X509 *ptr)
{
    return OpensslCallPtr::callChecked(lib::OpenSSLLib::SSL_X509_get_subject_name,
                                        ptr);
}

X509_NAME* _X509_get_issuer_name(X509 *ptr)
{
    return OpensslCallPtr::callChecked(lib::OpenSSLLib::SSL_X509_get_issuer_name,
                                        ptr);
}

void _ASN1_TIME_diff(int *pday, int *psec,
                              const ASN1_TIME *from, const ASN1_TIME *to)
{
    // If we don't have a 24 bit int, we can run into problems because a 16 bit integer can only
    // count days for 89 years.
    static_assert(sizeof(int) >= 3,
                  "Integer should have at least 24 bits to cover all ASN1_TIME differences in days");

    OpensslCallIsOne::callChecked(lib::OpenSSLLib::SSL_ASN1_TIME_diff, pday, psec, from, to);

    //double check that openssl keeps its promise that the signs are identical
    //if at least one of "days" or "seconds" is 0, then nothing needs to be checked
    if ((*pday < 0 && *psec > 0)
            || (*pday > 0 && *psec < 0)) {
        throw OpenSSLException("OpenSSL violates API convention");
    }
}

SSL_ASN1_TIME_Ptr _ASN1_TIME_from_time_t(time_t t)
{
    return SSL_ASN1_TIME_Ptr{OpensslCallPtr::callChecked(lib::OpenSSLLib::SSL_ASN1_TIME_set,
                            nullptr, t)};
}

SSL_ASN1_TIME_Ptr _ASN1_TIME_new()
{
    return SSL_ASN1_TIME_Ptr{OpensslCallPtr::callChecked(lib::OpenSSLLib::SSL_ASN1_TIME_new)};
}

SSL_ASN1_TIME_Ptr _ASN1_TIME_copy(const ASN1_TIME* t)
{
    ASN1_STRING *s = lib::OpenSSLLib::SSL_ASN1_STRING_dup(static_cast<const ASN1_STRING*>(t));
    if (s == nullptr) {
        throw OpenSSLException();
    }
    return SSL_ASN1_TIME_Ptr{static_cast<ASN1_TIME*>(s)};
}

void _ASN1_TIME_set_string(ASN1_TIME *s, const char *str)
{
    OpensslCallIsPositive::callChecked(lib::OpenSSLLib::SSL_ASN1_TIME_set_string, s, str);
}

/**
 * @brief Calculates the difference between epoch and an ASN1_TIME in seconds.
 * @param time the ASN1 time for which the difference should be calculated
 * @return the amount of seconds that are the equivalent of (time - epoch)
 */
std::int64_t secondsDiffToEpoch(const ASN1_TIME* time)
{
    auto epoch = _ASN1_TIME_from_time_t(0);
    //compute the offset between "time" and epoch in days and seconds.
    int days, seconds;
    _ASN1_TIME_diff(&days, &seconds, epoch.get(), time);

    // Convert days to seconds and add both.
    return 24 * 60 * 60 * static_cast<int64_t>(days) + static_cast<int64_t>(seconds);
}

enum class ComparisonResult { Lesser, Greater, Equal };

/**
 * @brief Compares an ASN1_TIME with a time_t.
 * @param asn1Time the ASN1_time to compare
 * @param timeT the time_t to compare
 * @return Lesser, if asn1Time < timeT; Equal, if asn1Time == timeT; Greater, if asn1Time > timeT
 */
ComparisonResult compare(const ASN1_TIME* asn1Time, std::time_t timeT)
{
    int days, seconds;

    // These are the limits of Asn1Time (1.1.0000:00:00:00, 31.12.9999:23:59:59)
    // as second diffs to 1.1.1970.
    constexpr int64_t minAsn1TimeAsTimeT = -62167219200;
    constexpr int64_t maxAsn1TimeAsTimeT = 253402300799;

    // First check if the time_t is outside of the ASN1_TIME range.
    if (timeT > maxAsn1TimeAsTimeT) {
        return ComparisonResult::Lesser;
    } else if (timeT < minAsn1TimeAsTimeT) {
        return ComparisonResult::Greater;
    }

    // Since it is within ASN1 range, we may safely cast it to one.
    auto timeTAsAsn1 = _ASN1_TIME_from_time_t(timeT);
    _ASN1_TIME_diff(&days, &seconds, asn1Time, timeTAsAsn1.get());
    if (days < 0 || seconds < 0) {
        return ComparisonResult::Greater;
    } else if (days > 0 || seconds > 0) {
        return ComparisonResult::Lesser;
    } else {
        return ComparisonResult::Equal;
    }
}

/**
 * @brief Checks that an ASN1 time is within a specific range.
 * @param time the ASN1 time that is checked.
 * @param minValue the minimum value it shall have, as time_t
 * @param maxValue the maximum value it shall have, as time_t
 * @throw OpenSSLException if the ASN1 time is outside of the specified range
 */
void checkAsn1TimeFitsIntoLimits(const ASN1_TIME* time, std::time_t minValue, std::time_t maxValue)
{
    if (compare(time, minValue) == ComparisonResult::Lesser) {
        throw OpenSSLException("ASN1_TIME is too small for new range");
    }
    if (compare(time, maxValue) == ComparisonResult::Greater) {
        throw OpenSSLException("ASN1_TIME is too big for new range");
    }
}

/**
 * @brief Convert an ASN1_TIME instance to a std::chrono::system_clock::time_point
 * @param [in] time An ASN1 encoded time object
 * @return A c++ time_point object with the same time
 */
time_point _asn1TimeToTimePoint(const ASN1_TIME *time)
{
    using std::chrono::system_clock;

    const auto epoch = system_clock::from_time_t(0);

    auto maxTimePoint = system_clock::time_point::max();
    auto maxTimePointAsTimeT = system_clock::to_time_t(maxTimePoint);
    auto minTimePoint = system_clock::time_point::min();
    auto minTimePointAsTimeT = system_clock::to_time_t(minTimePoint);

    checkAsn1TimeFitsIntoLimits(time, minTimePointAsTimeT, maxTimePointAsTimeT);

    return epoch + 1s * secondsDiffToEpoch(time);
}

/**
 * @brief Convert an ASN1_TIME instance to a time_t
 * @param [in] time An ASN1 encoded time object
 * @return A time_t object with the same time
 */
time_t _asn1TimeToTimeT(const ASN1_TIME *time)
{
    auto maxTimeT = std::numeric_limits<time_t>::max();
    auto minTimeT = std::numeric_limits<time_t>::min();

    checkAsn1TimeFitsIntoLimits(time, minTimeT, maxTimeT);

    // We know we can cast this to time_t since we just checked that it lies within its limits.
    return static_cast<time_t>(secondsDiffToEpoch(time));
}


time_point _X509_get_notBefore(X509* x)
{
    auto asn1time = _X509_get_notBefore_ASN1(x);
    return _asn1TimeToTimePoint(asn1time);
}

time_point _X509_get_notAfter(X509* x)
{
    auto asn1time = _X509_get_notAfter_ASN1(x);
    return _asn1TimeToTimePoint(asn1time);
}

ASN1_TIME* _X509_get_notBefore_ASN1(X509* x)
{
    auto asn1time = OpensslCallPtr::callChecked(lib::OpenSSLLib::SSL_X509_get_notBefore, x);
    return asn1time;
}

ASN1_TIME* _X509_get_notAfter_ASN1(X509* x)
{
    auto asn1time = OpensslCallPtr::callChecked(lib::OpenSSLLib::SSL_X509_get_notAfter, x);
    return asn1time;
}

SSL_EVP_PKEY_Ptr _X509_get_pubkey(X509* x)
{
    return SSL_EVP_PKEY_Ptr{OpensslCallPtr::callChecked(lib::OpenSSLLib::SSL_X509_get_pubkey,x)};
}

void _X509_set_subject_name(X509 *x, X509_NAME *name)
{
    OpensslCallIsOne::callChecked(lib::OpenSSLLib::SSL_X509_set_subject_name, x, name);
}

void _X509_set_issuer_name(X509 *x, X509_NAME *name)
{
    OpensslCallIsOne::callChecked(lib::OpenSSLLib::SSL_X509_set_issuer_name, x, name);
}

void _X509_set_pubkey(X509 *x, EVP_PKEY *key)
{
    OpensslCallIsOne::callChecked(lib::OpenSSLLib::SSL_X509_set_pubkey, x, key);
}

void _X509_set_notBefore(X509 *x, const time_point &t)
{
    auto asn1time = _ASN1_TIME_from_time_t(std::chrono::system_clock::to_time_t(t));
    _X509_set_notBefore_ASN1(x, asn1time.get());
}

void _X509_set_notAfter(X509 *x, const time_point &t)
{
    auto asn1time = _ASN1_TIME_from_time_t(std::chrono::system_clock::to_time_t(t));
    _X509_set_notAfter_ASN1(x, asn1time.get());
}

void _X509_set_notBefore_ASN1(X509 *x, const ASN1_TIME* asn1time)
{
    OpensslCallIsOne::callChecked(lib::OpenSSLLib::SSL_X509_set_notBefore, x, asn1time);
}

void _X509_set_notAfter_ASN1(X509 *x, const ASN1_TIME* asn1time)
{
    OpensslCallIsOne::callChecked(lib::OpenSSLLib::SSL_X509_set_notAfter, x, asn1time);
}

void _X509_sign(X509 *x, EVP_PKEY *pkey, DigestTypes type)
{
    auto dt = _getMDPtrFromDigestType(type);
    OpensslCallIsPositive::callChecked(lib::OpenSSLLib::SSL_X509_sign, x, pkey, dt);
}

std::vector<int> _X509_NAME_get_index_by_NID(X509_NAME* name, ASN1_NID nid)
{
    std::vector<int> result{};
    result.reserve(1); /* we expect this to return one result most of the time */
    auto rv = lib::OpenSSLLib::SSL_X509_NAME_get_index_by_NID(name, static_cast<int>(nid), -1);
    while (rv != -1) {
        result.push_back(rv);
        rv = lib::OpenSSLLib::SSL_X509_NAME_get_index_by_NID(name, static_cast<int>(nid), rv);
    }
    return result;
}

X509_NAME_ENTRY* _X509_NAME_get_entry(X509_NAME *name, int loc)
{
    return OpensslCallPtr::callChecked(lib::OpenSSLLib::SSL_X509_NAME_get_entry, name, loc);
}

std::string _X509_NAME_ENTRY_get_data(X509_NAME_ENTRY *entry)
{
    /* data does not need to be freed */
    auto *data = OpensslCallPtr::callChecked(lib::OpenSSLLib::SSL_X509_NAME_ENTRY_get_data, entry);

    BioObject bio{BioObject::Types::MEM};
    _ASN1_STRING_print_ex(bio.internal(), data);
    return bio.flushToString();
}

const EVP_CIPHER *_EVP_aes_256_cbc() {
    return OpensslCallPtr::callChecked(lib::OpenSSLLib::SSL_EVP_aes_256_cbc);
}

SSL_X509_EXTENSION_Ptr _X509V3_EXT_conf_nid(int ext_nid, X509V3_CTX* ctx, std::string value)
{
    return SSL_X509_EXTENSION_Ptr(OpensslCallPtr::callChecked(
                                      lib::OpenSSLLib::SSL_X509V3_EXT_conf_nid,
                                      nullptr,
                                      ctx,
                                      ext_nid,
                                      const_cast<char*>(value.c_str())));
}

void _X509V3_set_ctx(X509V3_CTX* ctx,
                    X509* issuer,
                    X509* subject)
{
    lib::OpenSSLLib::SSL_X509V3_set_ctx(ctx, issuer, subject, nullptr, nullptr, 0);
}

void _X509V3_set_ctx_nodb(X509V3_CTX* ctx)
{
    lib::OpenSSLLib::SSL_X509V3_set_ctx_nodb(ctx);
}

void _X509_add_ext(X509 *x, X509_EXTENSION *ex)
{
    //Location -1 means "add after the last extension"
    int locationInExtensions = -1;
    OpensslCallIsOne::callChecked(lib::OpenSSLLib::SSL_X509_add_ext, x, ex, locationInExtensions);
}

uint64_t Asn1IntegerToInt64(ASN1_INTEGER *number)
{
    auto maxLong = createManagedOpenSSLObject<SSL_ASN1_INTEGER_Ptr>();
    auto zero = createManagedOpenSSLObject<SSL_ASN1_INTEGER_Ptr>();
    OpensslCallIsOne::callChecked(lib::OpenSSLLib::SSL_ASN1_INTEGER_set, zero.get(), 0);
    OpensslCallIsOne::callChecked(lib::OpenSSLLib::SSL_ASN1_INTEGER_set, maxLong.get(),
                                  std::numeric_limits<long>::max());

    if (lib::OpenSSLLib::SSL_ASN1_INTEGER_cmp(number, maxLong.get()) > 0
        || lib::OpenSSLLib::SSL_ASN1_INTEGER_cmp(number, zero.get()) < 0) {
        throw OpenSSLException{"Number is out of the accepted range."};
    }

    return static_cast<uint64_t>(lib::OpenSSLLib::SSL_ASN1_INTEGER_get(number));
}

std::string Asn1IntegerToString(ASN1_INTEGER *number)
{
    auto bnNumber = SSL_BIGNUM_Ptr{OpensslCallPtr::callChecked(
                                            lib::OpenSSLLib::SSL_ASN1_INTEGER_to_BN,
                                            number, nullptr)};
    auto strNumber = SSL_char_Ptr{OpensslCallPtr::callChecked(
                                            lib::OpenSSLLib::SSL_BN_bn2dec, bnNumber.get())};
    // automatically convert into a string and free resources
    return strNumber.get();
}

std::vector<uint8_t> Asn1IntegerToBinary(ASN1_INTEGER *number)
{
    std::vector<uint8_t> serialNumber;
    auto bnNumber = SSL_BIGNUM_Ptr{OpensslCallPtr::callChecked(
                                            lib::OpenSSLLib::SSL_ASN1_INTEGER_to_BN,
                                            number, nullptr)};
    // The second parameter of BN_bn2bin must point to BN_num_bytes(a) bytes of memory.
    serialNumber.resize(OpensslCallIsPositive::callChecked(lib::OpenSSLLib::SSL_BN_num_bytes,
                                                           bnNumber.get()));
    int size = OpensslCallIsPositive::callChecked(lib::OpenSSLLib::SSL_BN_bn2bin,
                                                  bnNumber.get(),
                                                  serialNumber.data());
    // Just in case fewer bytes were used, truncate the std::vector.
    serialNumber.resize(size);
    return serialNumber;
}

uint64_t _X509_get_serialNumber(X509 *x)
{
    auto serialNumber = OpensslCallPtr::callChecked(lib::OpenSSLLib::SSL_X509_get_serialNumber, x);
    return Asn1IntegerToInt64(serialNumber);
}

void _X509_set_serialNumber(X509 *x, uint64_t serial)
{
    if (serial > std::numeric_limits<long>::max()) {
        throw OpenSSLException("Serial number is out of the accepted range.");
    }

    //This call triggers zero initialization, which is required by openssl
    auto asn1Serial = createManagedOpenSSLObject<SSL_ASN1_INTEGER_Ptr>();
    OpensslCallIsPositive::callChecked(lib::OpenSSLLib::SSL_ASN1_INTEGER_set, asn1Serial.get(), serial);
    OpensslCallIsPositive::callChecked(lib::OpenSSLLib::SSL_X509_set_serialNumber, x, asn1Serial.get());
}

std::string _X509_get_serialNumber_dec(X509* x)
{
    auto asn1SerialNumber = OpensslCallPtr::callChecked(
                                lib::OpenSSLLib::SSL_X509_get_serialNumber, x);
    return Asn1IntegerToString(asn1SerialNumber);
}

std::vector<uint8_t> _X509_get_serialNumber_bin(X509* x)
{
    auto asn1SerialNumber = OpensslCallPtr::callChecked(
                                lib::OpenSSLLib::SSL_X509_get_serialNumber, x);
    return Asn1IntegerToBinary(asn1SerialNumber);
}

SSL_X509_CRL_Ptr _d2i_X509_CRL_bio(BIO* bp)
{
    return SSL_X509_CRL_Ptr{OpensslCallPtr::callChecked(lib::OpenSSLLib::SSL_d2i_X509_CRL_bio, bp, nullptr)};
}

SSL_X509_CRL_Ptr _PEM_read_bio_X509_CRL(BIO* bp)
{
    return SSL_X509_CRL_Ptr{OpensslCallPtr::callChecked(lib::OpenSSLLib::SSL_PEM_read_bio_X509_CRL,
                                                        bp,
                                                        nullptr, // No "output pointer"
                                                        nullptr, // No password callback
                                                        nullptr)}; // No password
}

void _PEM_write_bio_X509_CRL(BIO* bio, X509_CRL* crl)
{
    OpensslCallIsOne::callChecked(lib::OpenSSLLib::SSL_PEM_write_bio_X509_CRL, bio, crl);
}

X509_NAME* _X509_CRL_get_issuer(const X509_CRL* crl)
{
    return OpensslCallPtr::callChecked(lib::OpenSSLLib::SSL_X509_CRL_get_issuer, crl);
}

void _X509_CRL_verify(X509_CRL *crl, EVP_PKEY *key)
{
    OpensslCallIsOne::callChecked(lib::OpenSSLLib::SSL_X509_CRL_verify, crl, key);
}

ASN1_TIME* _X509_CRL_get_lastUpdate(const X509_CRL* crl)
{
    return OpensslCallPtr::callChecked(lib::OpenSSLLib::SSL_X509_CRL_get_lastUpdate, crl);
}

ASN1_TIME* _X509_CRL_get_nextUpdate(const X509_CRL* crl)
{
    return OpensslCallPtr::callChecked(lib::OpenSSLLib::SSL_X509_CRL_get_nextUpdate, crl);
}

void _X509_STORE_CTX_set0_crls(X509_STORE_CTX* ctx, STACK_OF(X509_CRL)* crls)
{
    lib::OpenSSLLib::SSL_X509_STORE_CTX_set0_crls(ctx, crls);
}

SSL_ASN1_TIME_Ptr _ASN1_TIME_adj(time_t t, int days, long seconds)
{
    auto asn1Time = OpensslCallPtr::callChecked(lib::OpenSSLLib::SSL_ASN1_TIME_adj,
                                                nullptr, t, days, seconds);
    return SSL_ASN1_TIME_Ptr{asn1Time};
}

void _ASN1_STRING_print_ex(BIO *out, const ASN1_STRING *str)
{
    OpensslCallIsNonNegative::callChecked(lib::OpenSSLLib::SSL_ASN1_STRING_print_ex,
                                          out,
                                          const_cast<ASN1_STRING*>(str),
                                          0 /* no flags for escaping certain characters */);
}

void _X509_STORE_CTX_set_time(X509_STORE_CTX *ctx, time_t time)
{
    lib::OpenSSLLib::SSL_X509_STORE_CTX_set_time(ctx, 0 /* Time flags? Not used within OpenSSL */,
                                                 time);
}

void _EVP_PKEY_sign(EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen, const unsigned char *tbs, size_t tbslen)
{
    OpensslCallIsPositive::callChecked(lib::OpenSSLLib::SSL_EVP_PKEY_sign, ctx, sig, siglen, tbs, tbslen);
}

void _EVP_PKEY_sign_init(EVP_PKEY_CTX *ctx)
{
    OpensslCallIsPositive::callChecked(lib::OpenSSLLib::SSL_EVP_PKEY_sign_init, ctx);
}

void _EVP_PKEY_verify_init(EVP_PKEY_CTX *ctx)
{
    OpensslCallIsPositive::callChecked(lib::OpenSSLLib::SSL_EVP_PKEY_verify_init, ctx);
}

void _EVP_PKEY_verify(EVP_PKEY_CTX *ctx,
                     const unsigned char *sig, size_t siglen,
                     const unsigned char *tbs, size_t tbslen)
{
   OpensslCallIsPositive::callChecked(lib::OpenSSLLib::SSL_EVP_PKEY_verify,
                                             ctx,
                                             sig, siglen,
                                             tbs, tbslen);
}

void _EVP_PKEY_CTX_set_rsa_padding(EVP_PKEY_CTX *ctx, int pad)
{
    OpensslCallIsPositive::callChecked(lib::OpenSSLLib::SSL_EVP_PKEY_CTX_set_rsa_padding, ctx, pad);
}

void _EVP_PKEY_CTX_set_signature_md(EVP_PKEY_CTX *ctx, const EVP_MD* md)
{
    OpensslCallIsPositive::callChecked(lib::OpenSSLLib::SSL_EVP_PKEY_CTX_set_signature_md, ctx, md);
}
void _EVP_PKEY_CTX_set_rsa_pss_saltlen(EVP_PKEY_CTX *ctx, int len)
{
    OpensslCallIsPositive::callChecked(lib::OpenSSLLib::SSL_EVP_PKEY_CTX_set_rsa_pss_saltlen, ctx, len);
}
void _EVP_PKEY_CTX_set_rsa_mgf1_md(EVP_PKEY_CTX *ctx, const EVP_MD *md)
{
    OpensslCallIsPositive::callChecked(lib::OpenSSLLib::SSL_EVP_PKEY_CTX_set_rsa_mgf1_md, ctx, md);
}


void _EVP_PKEY_encrypt_init(EVP_PKEY_CTX *ctx)
{
    OpensslCallIsPositive::callChecked(lib::OpenSSLLib::SSL_EVP_PKEY_encrypt_init, ctx);
}

void _EVP_PKEY_encrypt(EVP_PKEY_CTX *ctx,
                       unsigned char *out, size_t *outlen,
                       const unsigned char *in, size_t inlen)
{
    OpensslCallIsPositive::callChecked(lib::OpenSSLLib::SSL_EVP_PKEY_encrypt,
                                       ctx, out, outlen,
                                       in, inlen);
}

void _EVP_PKEY_decrypt_init(EVP_PKEY_CTX *ctx)
{
    OpensslCallIsPositive::callChecked(lib::OpenSSLLib::SSL_EVP_PKEY_decrypt_init, ctx);
}

void _EVP_PKEY_decrypt(EVP_PKEY_CTX *ctx,
                       unsigned char *out, size_t *outlen,
                       const unsigned char *in, size_t inlen)
{
    OpensslCallIsPositive::callChecked(lib::OpenSSLLib::SSL_EVP_PKEY_decrypt,
                                       ctx, out, outlen,
                                       in, inlen);
}

void _EVP_PKEY_CTX_set_rsa_oaep_md(EVP_PKEY_CTX *ctx, const EVP_MD *md)
{
    OpensslCallIsPositive::callChecked(lib::OpenSSLLib::SSL_EVP_PKEY_CTX_set_rsa_oaep_md, ctx, md);
}

void _EVP_PKEY_CTX_set_rsa_oaep_label(EVP_PKEY_CTX *ctx, unsigned char *l, int llen)
{
    OpensslCallIsNonNegative::callChecked(lib::OpenSSLLib::SSL_EVP_PKEY_CTX_set_rsa_oaep_label, ctx, l, llen);
}

int _EVP_PKEY_CTX_get_rsa_oaep_label(EVP_PKEY_CTX *ctx, unsigned char *l)
{
    return OpensslCallIsNonNegative::callChecked(lib::OpenSSLLib::SSL_EVP_PKEY_CTX_get_rsa_oaep_label, ctx, l);
}

int _RSA_size(const RSA *r)
{
    return lib::OpenSSLLib::SSL_RSA_size(r);
}

int _EVP_MD_size(const EVP_MD *md)
{
    return lib::OpenSSLLib::SSL_EVP_MD_size(md);
}

void* _OPENSSL_malloc(int num)
{
    return OpensslCallPtr::callChecked(lib::OpenSSLLib::SSL_OPENSSL_malloc, num);
}

void _CRYPTO_malloc_init()
{
    return lib::OpenSSLLib::SSL_CRYPTO_malloc_init();
}

}  // ::openssl
}  //:: mococrw
