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

HsmEngine::HsmEngine(const std::string &id, const std::string &modulePath, const std::string &pin)
        : HSM(), _id(id), _modulePath(modulePath), _pin(pin)
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
    return _ENGINE_load_public_key(_engine.get(), keyID);
}

openssl::SSL_EVP_PKEY_Ptr HsmEngine::loadPrivateKey(const std::string &keyID) const
{
    return _ENGINE_load_private_key(_engine.get(), keyID);
}

openssl::SSL_EVP_PKEY_Ptr HsmEngine::generateKey(const RSASpec &spec,
                                                 const std::string &keyID,
                                                 const std::string &tokenLabel,
                                                 const std::string &keyLabel) const
{
    PKCS11_RSA_KGEN pkcs11_rsa_spec;
    pkcs11_rsa_spec.bits = spec.numberOfBits();
    PKCS11_KGEN_ATTRS pkcs11_rsa_kg;
    pkcs11_rsa_kg.type = EVP_PKEY_RSA;
    pkcs11_rsa_kg.kgen.rsa = &pkcs11_rsa_spec;
    pkcs11_rsa_kg.key_id = keyID.c_str();
    pkcs11_rsa_kg.token_label = tokenLabel.c_str();
    pkcs11_rsa_kg.key_label = keyLabel.c_str();

    _ENGINE_ctrl_cmd(_engine.get(), "KEYGEN", &pkcs11_rsa_kg);
    return loadPrivateKey(keyID);
}

openssl::SSL_EVP_PKEY_Ptr HsmEngine::generateKey(const ECCSpec &spec,
                                                 const std::string &keyID,
                                                 const std::string &tokenLabel,
                                                 const std::string &keyLabel) const
{
    PKCS11_EC_KGEN pkcs11_ec_spec;
    std::string curve{};
    try {
        curve = _EC_curve_nid2nist(int(spec.curve()));
    } catch (const OpenSSLException &e) {
        throw MoCOCrWException("Invalid EC NID. Check the ECCSpec.");
    }
    pkcs11_ec_spec.curve = curve.c_str();
    PKCS11_KGEN_ATTRS pkcs11_ec_kg;
    pkcs11_ec_kg.type = EVP_PKEY_EC;
    pkcs11_ec_kg.kgen.ec = &pkcs11_ec_spec;
    pkcs11_ec_kg.key_id = keyID.c_str();
    pkcs11_ec_kg.token_label = tokenLabel.c_str();
    pkcs11_ec_kg.key_label = keyLabel.c_str();

    _ENGINE_ctrl_cmd(_engine.get(), "KEYGEN", &pkcs11_ec_kg);
    return loadPrivateKey(keyID);
}
}  // namespace mococrw
