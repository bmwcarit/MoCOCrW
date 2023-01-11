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
#include "mococrw/hsm.h"
#include "libp11.h"
#include "mococrw/key.h"

namespace mococrw
{
using namespace openssl;

HsmEngine::HsmEngine(const std::string &id,
                     const std::string &modulePath,
                     const std::string &tokenLabel,
                     const std::string &pin)
        : _id(id), _modulePath(modulePath), _tokenLabel(tokenLabel), _pin(pin)
{
    // Fetch _engine via ID.
    _engine = _ENGINE_by_id(_id);

    _ENGINE_ctrl_cmd_string(_engine.get(), "MODULE_PATH", _modulePath);
    _ENGINE_ctrl_cmd_string(_engine.get(), "PIN", _pin);
    _ENGINE_init(_engine.get());
}

HsmEngine::~HsmEngine() { _ENGINE_finish(_engine.get()); }

openssl::SSL_EVP_PKEY_Ptr HsmEngine::loadPublicKey(const std::string &keyID) const
{
    // Do a copy here to avoid function side effects
    std::string evenLengthKeyID = keyID;
    if (keyID.length() % 2 != 0) {
        evenLengthKeyID = "0" + evenLengthKeyID;
    }
    /**
     *  TODO: use _tokenLabel and keyID to form a pkcs#11 uri as defined by rfc 7512 i.e.
     * pkcs11:token=some_label;id=123;object=some_label Rename keyID argument to keyURI
     */
    return _ENGINE_load_public_key(_engine.get(), evenLengthKeyID);
}

openssl::SSL_EVP_PKEY_Ptr HsmEngine::loadPrivateKey(const std::string &keyID) const
{
    // Do a copy here to avoid function side effects
    std::string evenLengthKeyID = keyID;
    if (keyID.length() % 2 != 0) {
        evenLengthKeyID = "0" + evenLengthKeyID;
    }
    /**
     *  TODO: use _tokenLabel and keyID to form a pkcs#11 uri as defined by rfc 7512 i.e.
     * pkcs11:token=some_label;id=123;object=some_label Rename keyID argument to keyURI
     */
    return _ENGINE_load_private_key(_engine.get(), evenLengthKeyID);
}

openssl::SSL_EVP_PKEY_Ptr HsmEngine::generateKey(const RSASpec &spec,
                                                 const std::string &keyID,
                                                 const std::string &keyLabel)
{
    /** Key IDs are stored on HSM as a series of bytes. In case of odd number of hex characters
     * in keyID, prepend 0. This should ideally be handled in lower level modules (libp11)
     * in this case but it's not. This makes sure key IDs are sanely set irrespective
     * of lower level implementation.
     */
    std::string evenLengthKeyID = keyID;
    if (keyID.length() % 2 != 0) {
        evenLengthKeyID = "0" + evenLengthKeyID;
    }
    PKCS11_RSA_KGEN pkcs11RSASpec;
    pkcs11RSASpec.bits = spec.numberOfBits();
    PKCS11_KGEN_ATTRS pkcs11RSAKeygen;
    pkcs11RSAKeygen.type = EVP_PKEY_RSA;
    pkcs11RSAKeygen.kgen.rsa = &pkcs11RSASpec;
    pkcs11RSAKeygen.key_id = evenLengthKeyID.c_str();
    pkcs11RSAKeygen.token_label = _tokenLabel.c_str();
    pkcs11RSAKeygen.key_label = keyLabel.c_str();

    _ENGINE_ctrl_cmd(_engine.get(), "KEYGEN", &pkcs11RSAKeygen);
    return loadPrivateKey(keyID);
}

openssl::SSL_EVP_PKEY_Ptr HsmEngine::generateKey(const ECCSpec &spec,
                                                 const std::string &keyID,
                                                 const std::string &keyLabel)
{
    std::string curve = spec.curveName();
    /** Key IDs are stored on HSM as a series of bytes. In case of odd number of hex characters
     * in keyID, prepend 0. This should ideally be handled in lower level modules (libp11)
     * in this case but it's not. This makes sure key IDs are sanely set irrespective
     * of lower level implementation.
     */
    std::string evenLengthKeyID = keyID;
    if (keyID.length() % 2 != 0) {
        evenLengthKeyID = "0" + evenLengthKeyID;
    }
    PKCS11_EC_KGEN pkcs11ECCSpec;
    pkcs11ECCSpec.curve = curve.c_str();
    PKCS11_KGEN_ATTRS pkcs11ECCKeygen;
    pkcs11ECCKeygen.type = EVP_PKEY_EC;
    pkcs11ECCKeygen.kgen.ec = &pkcs11ECCSpec;
    pkcs11ECCKeygen.key_id = evenLengthKeyID.c_str();
    pkcs11ECCKeygen.token_label = _tokenLabel.c_str();
    pkcs11ECCKeygen.key_label = keyLabel.c_str();

    _ENGINE_ctrl_cmd(_engine.get(), "KEYGEN", &pkcs11ECCKeygen);
    return loadPrivateKey(keyID);
}
}  // namespace mococrw
