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

#include "mococrw/dilithium.h"
#include <boost/format.hpp>
#include <boost/format/format_fwd.hpp>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <memory>
#include <vector>
#include "mococrw/asymmetric_crypto_ctx.h"
#include "mococrw/error.h"
#include "mococrw/key.h"
#include "mococrw/openssl_wrap.h"

extern "C" {
#include <dilithium-3.1/api.h>
#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/err.h>
#include <openssl/objects.h>
#include <openssl/x509.h>
}

namespace mococrw
{
using KeyTypes = AsymmetricKey::KeyTypes;

/*
 * The dilithium private key struct as returned by the backend
 * (iaik: http://javadoc.iaik.tugraz.at/iaik_jce/current/iaik/pkcs/pkcs8/PrivateKeyInfo.html)
 *
 * This is the internal struct inside the OCTET_STRING
 * privKey: contains the private key
 * pubKey: contains the public key
 * dilithiumForm: 3 for Dilithium3 and 5 for Dilithum5
 * bool1/bool2: The need/usage of bool1 and bool2 remains unknown
 */
struct dilithium_privkey_st
{
    ASN1_OCTET_STRING *privKey;
    ASN1_OCTET_STRING *pubKey;
    ASN1_INTEGER *dilithiumForm;
    ASN1_BOOLEAN bool1;
    ASN1_BOOLEAN bool2;
};

typedef struct dilithium_privkey_st DILITHIUM_PRIV;

// clang-format off
ASN1_SEQUENCE(DILITHIUM_PRIV_INTERNAL) =
        {
                ASN1_SIMPLE(DILITHIUM_PRIV, privKey, ASN1_OCTET_STRING),
                ASN1_SIMPLE(DILITHIUM_PRIV, pubKey, ASN1_OCTET_STRING),
                ASN1_SIMPLE(DILITHIUM_PRIV, dilithiumForm, ASN1_INTEGER),
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
 * The dilithium public key struct as returned by the backend
 * (iaik: http://javadoc.iaik.tugraz.at/iaik_jce/current/iaik/pkcs/pkcs8/PrivateKeyInfo.html)
 *
 * This is the internal struct inside the OCTET_STRING
 * pubKey: contains the public key
 * dilithiumForm: 3 for Dilithium3 and 5 for Dilithum5
 * bool1/bool2: The need/usage of bool1 and bool2 remains unknown
 */
struct dilithium_pubkey_st
{
    ASN1_OCTET_STRING *pubKey;
    ASN1_INTEGER *dilithiumForm;
    ASN1_BOOLEAN bool1;
    ASN1_BOOLEAN bool2;
};

typedef struct dilithium_pubkey_st DILITHIUM_PUB;

// clang-format off
ASN1_SEQUENCE(DILITHIUM_PUB_INTERNAL) =
        {
                ASN1_SIMPLE(DILITHIUM_PUB, pubKey, ASN1_OCTET_STRING),
                ASN1_SIMPLE(DILITHIUM_PUB, dilithiumForm, ASN1_INTEGER),
                ASN1_SIMPLE(DILITHIUM_PUB, bool1, ASN1_BOOLEAN),
                ASN1_SIMPLE(DILITHIUM_PUB, bool2, ASN1_BOOLEAN),
} static_ASN1_SEQUENCE_END_name(DILITHIUM_PUB, DILITHIUM_PUB_INTERNAL)


IMPLEMENT_ASN1_FUNCTIONS_fname(DILITHIUM_PUB, DILITHIUM_PUB_INTERNAL, dilithium_pub)

using DILITHIUM_PUB_Ptr = std::unique_ptr<DILITHIUM_PUB,
                                          openssl::SSLDeleter<DILITHIUM_PUB, dilithium_pub_free>>;
using DILITHIUM_PUB_SharedPtr = utility::SharedPtrTypeFromUniquePtr<DILITHIUM_PUB_Ptr>;
// clang-format on

KeyTypes getKeyTypeFromDilithiumForm(ASN1_INTEGER *asn1Int)
{
    int64_t dilithiumForm = openssl::_SSL_ASN1_INTEGER_get_int64(asn1Int);

    switch (dilithiumForm) {
        case 2:
            return KeyTypes::DILITHIUM2;
        case 3:
            return KeyTypes::DILITHIUM3;
        case 5:
            return KeyTypes::DILITHIUM5;
        default:
            throw MoCOCrWException("Invalid dilithium form set in the ASN.1 struct.");
    }
}

uint getPubKeySize(KeyTypes keyType)
{
    switch (keyType) {
        case KeyTypes::DILITHIUM2:
            return pqcrystals_dilithium2_PUBLICKEYBYTES;
        case KeyTypes::DILITHIUM3:
            return pqcrystals_dilithium3_PUBLICKEYBYTES;
        case KeyTypes::DILITHIUM5:
            return pqcrystals_dilithium5_PUBLICKEYBYTES;
            break;
        default:
            throw MoCOCrWException("Unsupported key type");
    }
}

uint getPrivKeySize(KeyTypes keyType)
{
    switch (keyType) {
        case KeyTypes::DILITHIUM2:
            return pqcrystals_dilithium2_SECRETKEYBYTES;
        case KeyTypes::DILITHIUM3:
            return pqcrystals_dilithium3_SECRETKEYBYTES;
        case KeyTypes::DILITHIUM5:
            return pqcrystals_dilithium5_SECRETKEYBYTES;
            break;
        default:
            throw MoCOCrWException("Unsupported key type");
    }
}

std::shared_ptr<DilithiumKeyImpl> DilithiumKeyImpl::parseAsn1PublicKey(
        const std::vector<uint8_t> &x509PubKey)
{
    const uint8_t *p = x509PubKey.data();
    auto pubKey = openssl::_d2i_X509_PUBKEY(p, x509PubKey.size());

    const unsigned char *pk = NULL;
    int ppklen;
    // Get the nested bit string
    // we can use get0 here, as pk is not used outside of this function
    // (d2i_dilithium_pub and the underlying ASN1_item_d2i_ex do an alloc according to the manpage)
    if (!X509_PUBKEY_get0_param(nullptr, &pk, &ppklen, nullptr, pubKey.get())) {
        printf("Can't retreive public key data.\n");
        throw MoCOCrWException("Cannot retreive public key bistring from x509 public key object.");
    }

    // parse the nested bitstring
    DILITHIUM_PUB_Ptr nestedPubKey = DILITHIUM_PUB_Ptr(d2i_dilithium_pub(nullptr, &pk, ppklen));
    // As we cannot use OpensslCallPtr as this is defined in openssl_wrap.cpp we need to manually
    // check the return value
    if (!nestedPubKey) {
        throw MoCOCrWException("Cannot read nested public key ASN.1 structure");
    }

    KeyTypes keyType = getKeyTypeFromDilithiumForm(nestedPubKey->dilithiumForm);

    return std::make_shared<DilithiumKeyImpl>(
            std::vector<uint8_t>(nestedPubKey->pubKey->data,
                                 nestedPubKey->pubKey->data + nestedPubKey->pubKey->length),
            keyType);
}

std::shared_ptr<DilithiumKeyImpl> DilithiumKeyImpl::parseAsn1PrivateKey(
        const std::vector<uint8_t> &pkcs8PrivKey)
{
    // Parse the RFC 5958 ASN.1 DER form
    auto p8inf = openssl::_SSL_d2i_PKCS8_PRIV_KEY_INFO(pkcs8PrivKey.data(), pkcs8PrivKey.size());

    const unsigned char *pk;
    int ppklen;
    // get the nested octet string
    // we can use get0 here, as pk is not used outside of this function
    // (d2i_dilithium_priv and the underlying ASN1_item_d2i_ex do an alloc according to the manpage)
    if (!PKCS8_pkey_get0(nullptr, &pk, &ppklen, nullptr, p8inf.get())) {
        throw MoCOCrWException("Cannot get private key data.\n");
    }

    // parse the nested octet string
    DILITHIUM_PRIV_Ptr nestedPrivKey(d2i_dilithium_priv(nullptr, &pk, ppklen));
    // As we cannot use OpensslCallPtr as this is defined in openssl_wrap.cpp we need to manually
    // check the return value
    if (!nestedPrivKey) {
        throw MoCOCrWException("Cannot read nested private key ASN.1 structure");
    }

    KeyTypes keyType = getKeyTypeFromDilithiumForm(nestedPrivKey->dilithiumForm);

    return std::make_shared<DilithiumKeyImpl>(
            std::vector<uint8_t>(nestedPrivKey->privKey->data,
                                 nestedPrivKey->privKey->data + nestedPrivKey->privKey->length),
            keyType);
}

DilithiumKeyImpl DilithiumKeyImpl::getPublicKey() const
{
    if (!isPrivateKey()) {
        return *this;
    }
    std::vector<uint8_t> public_key(getPubKeySize(_keyType));
    std::function<int(uint8_t *, const uint8_t *)> publicKeyGetterFunc;
    switch (_keyType) {
        case KeyTypes::DILITHIUM2:
            publicKeyGetterFunc = pqcrystals_dilithium2_ref_keypair_public_from_private;
            break;
        case KeyTypes::DILITHIUM3:
            publicKeyGetterFunc = pqcrystals_dilithium3_ref_keypair_public_from_private;
            break;
        case KeyTypes::DILITHIUM5:
            publicKeyGetterFunc = pqcrystals_dilithium5_ref_keypair_public_from_private;
            break;
        default:
            throw MoCOCrWException("Unsupported key type");
    }
    if (publicKeyGetterFunc(public_key.data(), _key_data.data())) {
        throw MoCOCrWException("Dilithium: Cannot get public key from private key.");
    }
    return DilithiumKeyImpl(public_key, _keyType);
}

bool DilithiumKeyImpl::hasValidKeySize() const
{
    if (getKeySize() != getPrivKeySize(_keyType) && getKeySize() != getPubKeySize(_keyType)) {
        return false;
    }
    return true;
}

bool DilithiumKeyImpl::isPrivateKey() const
{
    if (getKeySize() != getPrivKeySize(_keyType)) {
        if (getKeySize() != getPubKeySize(_keyType)) {
            throw MoCOCrWException(
                    "Invalid key length. Neither matches private nor public key length");
        }
        return false;
    }
    return true;
}

std::unique_ptr<DilithiumAsymmetricKey::Spec> DilithiumAsymmetricKey::getKeySpec() const
{
    return std::make_unique<DilithiumSpec>(getType());
}

DilithiumAsymmetricKeypair DilithiumAsymmetricKeypair::generate(
        const DilithiumAsymmetricKey::Spec &spec)
{
    return DilithiumAsymmetricKeypair(spec.generate());
}

DilithiumAsymmetricKey DilithiumSpec::generate() const
{
    std::vector<uint8_t> privateKey(getPrivKeySize(_keyType));
    // The public key is expected. Nullptr would lead to errors
    // So we need to create a vector although we throw away the value later.
    std::vector<uint8_t> publicKey(getPubKeySize(_keyType));

    switch (_keyType) {
        case KeyTypes::DILITHIUM2:
            if (pqcrystals_dilithium2_ref_keypair(publicKey.data(), privateKey.data())) {
                throw MoCOCrWException("Cannot create dilithium keypair.");
            }
            break;
        case KeyTypes::DILITHIUM3:
            if (pqcrystals_dilithium3_ref_keypair(publicKey.data(), privateKey.data())) {
                throw MoCOCrWException("Cannot create dilithium keypair.");
            }
            break;
        case KeyTypes::DILITHIUM5:
            if (pqcrystals_dilithium5_ref_keypair(publicKey.data(), privateKey.data())) {
                throw MoCOCrWException("Cannot create dilithium keypair.");
            }
            break;
        default:
            throw MoCOCrWException("The used dilithium key type is not supported.");
    }

    return DilithiumAsymmetricKey(std::make_shared<DilithiumKeyImpl>(privateKey, _keyType));
}

template <class Key>
class DilithiumSignatureImpl
{
public:
    DilithiumSignatureImpl(const Key &key) : _key(key) {}

protected:
    Key _key;
};

class DilithiumSigningCtx::Impl : public DilithiumSignatureImpl<DilithiumAsymmetricPrivateKey>
{
public:
    using DilithiumSignatureImpl<DilithiumAsymmetricPrivateKey>::DilithiumSignatureImpl;
    std::vector<uint8_t> signMessage(const std::vector<uint8_t> &message)
    {
        std::vector<uint8_t> signature;
        size_t signatureLength;
        std::function<int(uint8_t *, size_t *, const uint8_t *, size_t, const uint8_t *)>
                sign_function;
        switch (_key.getType()) {
            case KeyTypes::DILITHIUM2:
                signature.resize(pqcrystals_dilithium2_BYTES);
                sign_function = pqcrystals_dilithium2_ref_signature;
                break;
            case KeyTypes::DILITHIUM3:
                signature.resize(pqcrystals_dilithium3_BYTES);
                sign_function = pqcrystals_dilithium3_ref_signature;
                break;
            case KeyTypes::DILITHIUM5:
                signature.resize(pqcrystals_dilithium5_BYTES);
                sign_function = pqcrystals_dilithium5_ref_signature;
                break;
            default:
                throw MoCOCrWException("Invalid key type for dilithium");
        }

        if (sign_function(
                    reinterpret_cast<uint8_t *>(signature.data()),
                    &signatureLength,
                    reinterpret_cast<const uint8_t *>(message.data()),
                    message.size(),
                    reinterpret_cast<const uint8_t *>(_key._internal()->getKeyData().data()))) {
            throw MoCOCrWException("Failure signing with dilithium key.");
        }

        return signature;
    }
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

class DilithiumVerificationCtx::Impl : public DilithiumSignatureImpl<DilithiumAsymmetricPublicKey>
{
public:
    using DilithiumSignatureImpl<DilithiumAsymmetricPublicKey>::DilithiumSignatureImpl;

    void verifyMessage(const std::vector<uint8_t> &signature, const std::vector<uint8_t> &message)
    {
        std::function<int(const uint8_t *, size_t, const uint8_t *, size_t, const uint8_t *)>
                verifyFunction;
        switch (_key.getType()) {
            case KeyTypes::DILITHIUM2:
                verifyFunction = pqcrystals_dilithium2_ref_verify;
                break;
            case KeyTypes::DILITHIUM3:
                verifyFunction = pqcrystals_dilithium3_ref_verify;
                break;
            case KeyTypes::DILITHIUM5:
                verifyFunction = pqcrystals_dilithium5_ref_verify;
                break;
            default:
                throw MoCOCrWException("Invalid key type for dilithium");
        }

        if (verifyFunction(signature.data(),
                           signature.size(),
                           message.data(),
                           message.size(),
                           reinterpret_cast<const uint8_t *>(
                                   _key._internal()->getPublicKey().getKeyData().data()))) {
            throw MoCOCrWException("Dilithium: Signature validation failed.");
        }
    }
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
