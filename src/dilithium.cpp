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

#include <boost/format.hpp>
#include <boost/format/format_fwd.hpp>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <memory>
#include <vector>

extern "C" {
/* As we expect dilithium to become part of openssl, we directly include
 * openssl and dilithium headers here as they can be removed later.
 */
#include <dilithium-3.1/api.h>
#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/err.h>
#include <openssl/objects.h>
#include <openssl/x509.h>
}

#include "mococrw/asymmetric_crypto_ctx.h"
#include "mococrw/dilithium.h"
#include "mococrw/error.h"
#include "mococrw/key.h"
#include "mococrw/openssl_wrap.h"

namespace mococrw
{
using KeyTypes = AsymmetricKey::KeyTypes;

/*
 * The dilithium private key struct (see RFC5208 and iaik:
 * http://javadoc.iaik.tugraz.at/iaik_jce/current/iaik/pkcs/pkcs8/PrivateKeyInfo.html)
 *
 * This is the internal structure contained in the PrivateKey element of the PrivateKeyInfo
 * structure
 * privKey: contains the private key
 * pubKey: contains the public key
 * dilithiumParameterSet: 3 for Dilithium3 and 5 for Dilithum5
 * bool1/bool2: The need/usage of bool1 and bool2 remains unknown
 */
typedef struct dilithium_privkey_st
{
    ASN1_OCTET_STRING *privKey;
    ASN1_OCTET_STRING *pubKey;
    ASN1_INTEGER *dilithiumParameterSet;
    ASN1_BOOLEAN bool1;
    ASN1_BOOLEAN bool2;
} DILITHIUM_PRIV;

// clang-format off
ASN1_SEQUENCE(DILITHIUM_PRIV_INTERNAL) = {
    ASN1_SIMPLE(DILITHIUM_PRIV, privKey, ASN1_OCTET_STRING),
    ASN1_SIMPLE(DILITHIUM_PRIV, pubKey, ASN1_OCTET_STRING),
    ASN1_SIMPLE(DILITHIUM_PRIV, dilithiumParameterSet, ASN1_INTEGER),
    ASN1_SIMPLE(DILITHIUM_PRIV, bool1, ASN1_BOOLEAN),
    ASN1_SIMPLE(DILITHIUM_PRIV, bool2, ASN1_BOOLEAN),
} static_ASN1_SEQUENCE_END_name(DILITHIUM_PRIV, DILITHIUM_PRIV_INTERNAL)

IMPLEMENT_ASN1_FUNCTIONS_fname(DILITHIUM_PRIV,
                               DILITHIUM_PRIV_INTERNAL,
                               dilithium_priv)

using DILITHIUM_PRIV_Ptr = std::unique_ptr<DILITHIUM_PRIV,
                                           openssl::SSLDeleter<DILITHIUM_PRIV, dilithium_priv_free>>;
using DILITHIUM_PRIV_SharedPtr = utility::SharedPtrTypeFromUniquePtr<DILITHIUM_PRIV_Ptr>;
// clang-format on

/*
 * The dilithium public key struct (see RFC5280 and iaik:
 * http://javadoc.iaik.tugraz.at/iaik_jce/current/iaik/pkcs/pkcs8/PrivateKeyInfo.html)
 *
 * This is the internal structure contained in the PrivateKey element of the SubjectPublicKeyInfo
 * structure:
 * pubKey: contains the public key
 * dilithiumParameterSet: 3 for Dilithium3 and 5 for Dilithum5
 * bool1/bool2: The need/usage of bool1 and bool2 remains unknown
 */
typedef struct dilithium_pubkey_st
{
    ASN1_OCTET_STRING *pubKey;
    ASN1_INTEGER *dilithiumParameterSet;
    ASN1_BOOLEAN bool1;
    ASN1_BOOLEAN bool2;
} DILITHIUM_PUB;

// clang-format off
ASN1_SEQUENCE(DILITHIUM_PUB_INTERNAL) = {
    ASN1_SIMPLE(DILITHIUM_PUB, pubKey, ASN1_OCTET_STRING),
    ASN1_SIMPLE(DILITHIUM_PUB, dilithiumParameterSet, ASN1_INTEGER),
    ASN1_SIMPLE(DILITHIUM_PUB, bool1, ASN1_BOOLEAN),
    ASN1_SIMPLE(DILITHIUM_PUB, bool2, ASN1_BOOLEAN),
} static_ASN1_SEQUENCE_END_name(DILITHIUM_PUB, DILITHIUM_PUB_INTERNAL)


IMPLEMENT_ASN1_FUNCTIONS_fname(DILITHIUM_PUB, DILITHIUM_PUB_INTERNAL, dilithium_pub)

using DILITHIUM_PUB_Ptr = std::unique_ptr<DILITHIUM_PUB,
                                          openssl::SSLDeleter<DILITHIUM_PUB, dilithium_pub_free>>;
using DILITHIUM_PUB_SharedPtr = utility::SharedPtrTypeFromUniquePtr<DILITHIUM_PUB_Ptr>;
// clang-format on

DilithiumKeyImpl::DilithiumParameterSet getKeyTypeFromDilithiumParameterSet(
        const ASN1_INTEGER *asn1Int)
{
    int64_t dilithiumParameterSet = openssl::_SSL_ASN1_INTEGER_get_int64(asn1Int);

    switch (dilithiumParameterSet) {
        case 2:
            return DilithiumKeyImpl::DilithiumParameterSet::DILITHIUM2;
        case 3:
            return DilithiumKeyImpl::DilithiumParameterSet::DILITHIUM3;
        case 5:
            return DilithiumKeyImpl::DilithiumParameterSet::DILITHIUM5;
        default:
            throw MoCOCrWException("Invalid dilithium parameter set set in the ASN.1 struct.");
    }
}

uint getPubKeySize(DilithiumKeyImpl::DilithiumParameterSet paramSet)
{
    switch (paramSet) {
        case DilithiumKeyImpl::DilithiumParameterSet::DILITHIUM2:
            return pqcrystals_dilithium2_PUBLICKEYBYTES;
        case DilithiumKeyImpl::DilithiumParameterSet::DILITHIUM3:
            return pqcrystals_dilithium3_PUBLICKEYBYTES;
        case DilithiumKeyImpl::DilithiumParameterSet::DILITHIUM5:
            return pqcrystals_dilithium5_PUBLICKEYBYTES;
            break;
        default:
            throw MoCOCrWException("Unsupported parameter set");
    }
}

uint getPrivKeySize(DilithiumKeyImpl::DilithiumParameterSet paramSet)
{
    switch (paramSet) {
        case DilithiumKeyImpl::DilithiumParameterSet::DILITHIUM2:
            return pqcrystals_dilithium2_SECRETKEYBYTES;
        case DilithiumKeyImpl::DilithiumParameterSet::DILITHIUM3:
            return pqcrystals_dilithium3_SECRETKEYBYTES;
        case DilithiumKeyImpl::DilithiumParameterSet::DILITHIUM5:
            return pqcrystals_dilithium5_SECRETKEYBYTES;
            break;
        default:
            throw MoCOCrWException("Unsupported parameter set");
    }
}

std::shared_ptr<DilithiumKeyImpl> DilithiumKeyImpl::readPublicKeyFromDER(
        const std::vector<uint8_t> &x509PubKey)
{
    const uint8_t *p = x509PubKey.data();
    auto pubKey = openssl::_d2i_X509_PUBKEY(p, x509PubKey.size());

    const unsigned char *pk = NULL;
    int ppklen;
    // Get the nested bit string
    // we can use get0 here, as pk is not used outside of this function
    // (d2i_dilithium_pub and the underlying ASN1_item_d2i_ex copies the data according to the
    // manpage)
    if (!X509_PUBKEY_get0_param(nullptr, &pk, &ppklen, nullptr, pubKey.get())) {
        throw MoCOCrWException("Cannot retreive public key bistring from x509 public key object.");
    }

    auto nestedPubKey = DILITHIUM_PUB_Ptr(d2i_dilithium_pub(nullptr, &pk, ppklen));
    // As we cannot use OpensslCallPtr as this is defined in openssl_wrap.cpp we need to manually
    // check the return value
    if (!nestedPubKey) {
        throw MoCOCrWException("Cannot read nested public key ASN.1 structure");
    }

    DilithiumKeyImpl::DilithiumParameterSet paramSet =
            getKeyTypeFromDilithiumParameterSet(nestedPubKey->dilithiumParameterSet);

    return std::make_shared<DilithiumKeyImpl>(
            std::vector<uint8_t>(nestedPubKey->pubKey->data,
                                 nestedPubKey->pubKey->data + nestedPubKey->pubKey->length),
            paramSet,
            false);
}

std::shared_ptr<DilithiumKeyImpl> DilithiumKeyImpl::readPrivateKeyFromDER(
        const std::vector<uint8_t> &pkcs8PrivKey)
{
    // Parse the RFC 5958 ASN.1 DER form
    auto p8inf = openssl::_SSL_d2i_PKCS8_PRIV_KEY_INFO(pkcs8PrivKey.data(), pkcs8PrivKey.size());

    const unsigned char *pk;
    int ppklen;
    // get the nested octet string
    // we can use get0 here, as pk is not used outside of this function
    // (d2i_dilithium_priv and the underlying ASN1_item_d2i_ex copies the data according to the
    // manpage)
    if (!PKCS8_pkey_get0(nullptr, &pk, &ppklen, nullptr, p8inf.get())) {
        throw MoCOCrWException("Cannot get private key data.\n");
    }

    // parse the nested octet string
    auto nestedPrivKey = DILITHIUM_PRIV_Ptr(d2i_dilithium_priv(nullptr, &pk, ppklen));
    // As we cannot use OpensslCallPtr as this is defined in openssl_wrap.cpp we need to manually
    // check the return value
    if (!nestedPrivKey) {
        throw MoCOCrWException("Cannot read nested private key ASN.1 structure");
    }

    DilithiumKeyImpl::DilithiumParameterSet paramSet =
            getKeyTypeFromDilithiumParameterSet(nestedPrivKey->dilithiumParameterSet);

    return std::make_shared<DilithiumKeyImpl>(
            std::vector<uint8_t>(nestedPrivKey->privKey->data,
                                 nestedPrivKey->privKey->data + nestedPrivKey->privKey->length),
            paramSet,
            true);
}

DilithiumKeyImpl DilithiumKeyImpl::getPublicKey() const
{
    if (!isPrivateKey()) {
        return *this;
    }
    std::vector<uint8_t> public_key(getPubKeySize(_paramSet));
    int ret = -1;
    switch (_paramSet) {
        case DilithiumParameterSet::DILITHIUM2:
            ret = pqcrystals_dilithium2_ref_keypair_public_from_private(public_key.data(),
                                                                        _key_data.data());
            break;
        case DilithiumParameterSet::DILITHIUM3:
            ret = pqcrystals_dilithium3_ref_keypair_public_from_private(public_key.data(),
                                                                        _key_data.data());
            break;
        case DilithiumParameterSet::DILITHIUM5:
            ret = pqcrystals_dilithium5_ref_keypair_public_from_private(public_key.data(),
                                                                        _key_data.data());
            break;
        default:
            throw MoCOCrWException("Unsupported parameter set");
    }
    if (ret) {
        throw MoCOCrWException("Dilithium: Cannot get public key from private key.");
    }
    return DilithiumKeyImpl(public_key, _paramSet, false);
}

bool DilithiumKeyImpl::hasValidKeySize() const
{
    if (_is_private_key) {
        if (getKeySize() == getPrivKeySize(_paramSet)) {
            return true;
        }
    } else {
        if (getKeySize() == getPubKeySize(_paramSet)) {
            return true;
        }
    }
    return false;
}

bool DilithiumKeyImpl::isPrivateKey() const { return _is_private_key; }

std::unique_ptr<DilithiumAsymmetricKey::Spec> DilithiumAsymmetricKey::getKeySpec() const
{
    return std::make_unique<DilithiumSpec>(_internal()->getDilithiumParameterSet());
}

DilithiumAsymmetricPublicKey DilithiumAsymmetricPublicKey::readPublicKeyfromDER(
        const std::vector<uint8_t> &asn1Data)
{
    return DilithiumAsymmetricPublicKey(DilithiumKeyImpl::readPublicKeyFromDER(asn1Data));
}

DilithiumAsymmetricKeypair DilithiumAsymmetricKeypair::readPrivateKeyfromDER(
        const std::vector<uint8_t> &asn1Data)
{
    return DilithiumAsymmetricKeypair(DilithiumKeyImpl::readPrivateKeyFromDER(asn1Data));
}

DilithiumAsymmetricKeypair DilithiumAsymmetricKeypair::generate(
        const DilithiumAsymmetricKey::Spec &spec)
{
    return DilithiumAsymmetricKeypair(spec.generate());
}

DilithiumAsymmetricKey DilithiumSpec::generate() const
{
    std::vector<uint8_t> privateKey(getPrivKeySize(_paramSet));
    // The dilithium implementation returns both the public and the private key
    // on generation. If a nullptr is provided as public key, this will lead to
    // an error.
    // So we need to create a vector although we throw away the value later.
    std::vector<uint8_t> publicKey(getPubKeySize(_paramSet));

    int ret = -1;
    switch (_paramSet) {
        case DilithiumKeyImpl::DilithiumParameterSet::DILITHIUM2:
            ret = pqcrystals_dilithium2_ref_keypair(publicKey.data(), privateKey.data());
            break;
        case DilithiumKeyImpl::DilithiumParameterSet::DILITHIUM3:
            ret = pqcrystals_dilithium3_ref_keypair(publicKey.data(), privateKey.data());
            break;
        case DilithiumKeyImpl::DilithiumParameterSet::DILITHIUM5:
            ret = pqcrystals_dilithium5_ref_keypair(publicKey.data(), privateKey.data());
            break;
        default:
            throw MoCOCrWException("The used dilithium parameter set is not supported.");
    }

    if (ret) {
        throw MoCOCrWException("Cannot create dilithium keypair.");
    }

    return DilithiumAsymmetricKey(std::make_shared<DilithiumKeyImpl>(privateKey, _paramSet, true));
}

class DilithiumSigningCtx::Impl
{
public:
    Impl(const DilithiumAsymmetricPrivateKey &key) : _key(key){};
    std::vector<uint8_t> signMessage(const std::vector<uint8_t> &message)
    {
        std::vector<uint8_t> signature;
        size_t signatureLength;
        int ret = -1;
        if (_key.getType() != AsymmetricKey::KeyTypes::DILITHIUM) {
            throw MoCOCrWException("Key used for signing is not a dilithium key.");
        }
        switch (_key._internal()->getDilithiumParameterSet()) {
            case DilithiumKeyImpl::DilithiumParameterSet::DILITHIUM2:
                signature.resize(pqcrystals_dilithium2_BYTES);
                ret = pqcrystals_dilithium2_ref_signature(signature.data(),
                                                          &signatureLength,
                                                          message.data(),
                                                          message.size(),
                                                          _key._internal()->getKeyData().data());
                break;
            case DilithiumKeyImpl::DilithiumParameterSet::DILITHIUM3:
                signature.resize(pqcrystals_dilithium3_BYTES);
                ret = pqcrystals_dilithium3_ref_signature(signature.data(),
                                                          &signatureLength,
                                                          message.data(),
                                                          message.size(),
                                                          _key._internal()->getKeyData().data());
                break;
            case DilithiumKeyImpl::DilithiumParameterSet::DILITHIUM5:
                signature.resize(pqcrystals_dilithium5_BYTES);
                ret = pqcrystals_dilithium5_ref_signature(signature.data(),
                                                          &signatureLength,
                                                          message.data(),
                                                          message.size(),
                                                          _key._internal()->getKeyData().data());
                break;
            default:
                throw MoCOCrWException("Invalid parameter set for dilithium");
        }

        if (ret) {
            throw MoCOCrWException("Failure signing with dilithium key.");
        }

        return signature;
    }

private:
    DilithiumAsymmetricPrivateKey _key;
};

DilithiumSigningCtx::DilithiumSigningCtx(const DilithiumAsymmetricPrivateKey &key)
        : _impl(std::make_unique<DilithiumSigningCtx::Impl>(key))
{
}

DilithiumSigningCtx::~DilithiumSigningCtx() = default;

DilithiumSigningCtx::DilithiumSigningCtx(const DilithiumSigningCtx &other)
        : _impl(std::make_unique<DilithiumSigningCtx::Impl>(*(other._impl)))
{
}

DilithiumSigningCtx &DilithiumSigningCtx::operator=(const DilithiumSigningCtx &other)
{
    _impl = std::make_unique<DilithiumSigningCtx::Impl>(*(other._impl));
    return *this;
}

std::vector<uint8_t> DilithiumSigningCtx::signMessage(const std::vector<uint8_t> &message)
{
    return _impl->signMessage(message);
}

class DilithiumVerificationCtx::Impl
{
public:
    Impl(const DilithiumAsymmetricPublicKey &key) : _key(key){};

    void verifyMessage(const std::vector<uint8_t> &signature, const std::vector<uint8_t> &message)
    {
        int ret = -1;
        if (_key.getType() != AsymmetricKey::KeyTypes::DILITHIUM) {
            throw MoCOCrWException("Key used for signing is not a dilithium key.");
        }
        switch (_key._internal()->getDilithiumParameterSet()) {
            case DilithiumKeyImpl::DilithiumParameterSet::DILITHIUM2:
                ret = pqcrystals_dilithium2_ref_verify(
                        signature.data(),
                        signature.size(),
                        message.data(),
                        message.size(),
                        _key._internal()->getPublicKey().getKeyData().data());
                break;
            case DilithiumKeyImpl::DilithiumParameterSet::DILITHIUM3:
                ret = pqcrystals_dilithium3_ref_verify(
                        signature.data(),
                        signature.size(),
                        message.data(),
                        message.size(),
                        _key._internal()->getPublicKey().getKeyData().data());
                break;
            case DilithiumKeyImpl::DilithiumParameterSet::DILITHIUM5:
                ret = pqcrystals_dilithium5_ref_verify(
                        signature.data(),
                        signature.size(),
                        message.data(),
                        message.size(),
                        _key._internal()->getPublicKey().getKeyData().data());
                break;
            default:
                throw MoCOCrWException("Invalid parameter set for dilithium");
        }

        if (ret) {
            throw MoCOCrWException("Dilithium: Signature validation failed.");
        }
    }

private:
    DilithiumAsymmetricPublicKey _key;
};

DilithiumVerificationCtx::DilithiumVerificationCtx(const DilithiumAsymmetricPublicKey &key)
        : _impl(std::make_unique<DilithiumVerificationCtx::Impl>(key))
{
}

DilithiumVerificationCtx::~DilithiumVerificationCtx() = default;

DilithiumVerificationCtx::DilithiumVerificationCtx(const DilithiumVerificationCtx &other)
        : _impl(std::make_unique<DilithiumVerificationCtx::Impl>(*(other._impl)))
{
}

DilithiumVerificationCtx &DilithiumVerificationCtx::operator=(const DilithiumVerificationCtx &other)
{
    _impl = std::make_unique<DilithiumVerificationCtx::Impl>(*(other._impl));
    return *this;
}

void DilithiumVerificationCtx::verifyMessage(const std::vector<uint8_t> &signature,
                                             const std::vector<uint8_t> &message)
{
    _impl->verifyMessage(signature, message);
}
}  // namespace mococrw
