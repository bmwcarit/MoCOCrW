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

#include <iomanip>
#include <sstream>

#include "libp11.h"

#include "mococrw/error.h"
#include "mococrw/key.h"

namespace mococrw
{
using namespace openssl;

namespace
{
/**
 * @brief Transforms given input to pct encoded string (see RFC 3986)
 */
std::string pctEncode(const std::vector<uint8_t> &bytes)
{
    if (bytes.size() == 0) {
        return {};
    }
    std::stringstream result;
    for (int byte : bytes) {
        result << "%" << std::hex << std::setfill('0') << std::setw(2) << byte;
    }
    return result.str();
}
}  // namespace

HsmEngine::HsmEngine(const std::string &id,
                     const std::string &modulePath,
                     const std::string &tokenLabel,
                     const std::string &pin)
        : _id(id), _modulePath(modulePath), _tokenLabel(tokenLabel)
{
    // Fetch _engine via ID.
    _engine = _ENGINE_by_id(_id);

    _ENGINE_ctrl_cmd_string(_engine.get(), "MODULE_PATH", _modulePath);
    _ENGINE_ctrl_cmd_string(_engine.get(), "PIN", pin);
    _ENGINE_init(_engine.get());
}

HsmEngine::~HsmEngine() { _ENGINE_finish(_engine.get()); }

std::string HsmEngine::_constructPkcs11URI(const std::string &keyLabel,
                                           const std::vector<uint8_t> &keyID) const
{
    if (keyID.empty()) {
        // libp11 doesn't fetch keys in deterministic manner if multiple keys have the
        // the same label and we provide empty keyID
        throw MoCOCrWException("keyID can't be empty");
    }
    auto keyIDPctEncoded = pctEncode(keyID);
    std::string pkcs11URI = "pkcs11:token=" + _tokenLabel + ";id=" + keyIDPctEncoded;
    if (!keyLabel.empty()) {
        pkcs11URI += ";object=" + keyLabel;
    }
    return pkcs11URI;
}

openssl::SSL_EVP_PKEY_Ptr HsmEngine::loadPublicKey(const std::string &keyLabel,
                                                   const std::vector<uint8_t> &keyID) const
{
    auto pkcs11URI = _constructPkcs11URI(keyLabel, keyID);
    try {
        return _ENGINE_load_public_key(_engine.get(), pkcs11URI);
    } catch (const OpenSSLException &e) {
        // The current OpenSSLException catch-all approach makes it difficult to distinguish
        // different types of errors. In order to specifically identify the case where the passed
        // key is unknown, we check that the error stems from the pkcs11 engine and that the
        // reason is "object not found".
        if (e.getLib() == "pkcs11 engine" && e.getReason() == "object not found") {
            throw MoCOCrWException("Unable to load public key. Public key not found!");
        }
        // If not Unknown Key error, then throw again the original exception.
        throw;
    }
}

openssl::SSL_EVP_PKEY_Ptr HsmEngine::loadPrivateKey(const std::string &keyLabel,
                                                    const std::vector<uint8_t> &keyID) const
{
    auto pkcs11URI = _constructPkcs11URI(keyLabel, keyID);
    try {
        return _ENGINE_load_private_key(_engine.get(), pkcs11URI);
    } catch (const OpenSSLException &e) {
        if (e.getLib() == "pkcs11 engine" && e.getReason() == "object not found") {
            throw MoCOCrWException("Unable to load private key. Private key not found!");
        }
        throw;
    }
}

openssl::SSL_EVP_PKEY_Ptr HsmEngine::generateKey(const RSASpec &spec,
                                                 const std::string &keyLabel,
                                                 const std::vector<uint8_t> &keyID)
{
    try {
        // We need to make sure that we don't have 2 keys with the same ID.
        // For that we need to pass empty keyLabel. Otherwise libp11 tries to find
        // a key with exact keyLabel/keyID combination. This means that libp11 might
        // not recognize that the key with the same ID is already there.
        loadPrivateKey("", keyID);
    } catch (const MoCOCrWException &e) {
        if (e.what() == std::string("Unable to load private key. Private key not found!")) {
            std::string keyIDHexString = utility::toHex(keyID);
            PKCS11_RSA_KGEN pkcs11RSASpec;
            pkcs11RSASpec.bits = spec.numberOfBits();
            PKCS11_KGEN_ATTRS pkcs11RSAKeygen;
            pkcs11RSAKeygen.type = EVP_PKEY_RSA;
            pkcs11RSAKeygen.kgen.rsa = &pkcs11RSASpec;
            pkcs11RSAKeygen.key_id = keyIDHexString.c_str();
            pkcs11RSAKeygen.token_label = _tokenLabel.c_str();
            pkcs11RSAKeygen.key_label = keyLabel.c_str();

            _ENGINE_ctrl_cmd(_engine.get(), "KEYGEN", &pkcs11RSAKeygen);
            return loadPrivateKey(keyLabel, keyID);
        }
        throw;
    }
    throw MoCOCrWException("Key with that keyID already exists");
}

openssl::SSL_EVP_PKEY_Ptr HsmEngine::generateKey(const ECCSpec &spec,
                                                 const std::string &keyLabel,
                                                 const std::vector<uint8_t> &keyID)
{
    try {
        // We need to make sure that we don't have 2 keys with the same ID.
        // For that we need to pass empty keyLabel. Otherwise libp11 tries to find
        // a key with exact keyLabel/keyID combination. This means that libp11 might
        // not recognize that the key with the same ID is already there.
        loadPrivateKey("", keyID);
    } catch (const MoCOCrWException &e) {
        if (e.what() == std::string("Unable to load private key. Private key not found!")) {
            std::string curve = spec.curveName();
            std::string keyIDHexString = utility::toHex(keyID);
            PKCS11_EC_KGEN pkcs11ECCSpec;
            pkcs11ECCSpec.curve = curve.c_str();
            PKCS11_KGEN_ATTRS pkcs11ECCKeygen;
            pkcs11ECCKeygen.type = EVP_PKEY_EC;
            pkcs11ECCKeygen.kgen.ec = &pkcs11ECCSpec;
            pkcs11ECCKeygen.key_id = keyIDHexString.c_str();
            pkcs11ECCKeygen.token_label = _tokenLabel.c_str();
            pkcs11ECCKeygen.key_label = keyLabel.c_str();

            _ENGINE_ctrl_cmd(_engine.get(), "KEYGEN", &pkcs11ECCKeygen);
            return loadPrivateKey(keyLabel, keyID);
        }
        throw;
    }
    throw MoCOCrWException("Key with that keyID already exists");
}
}  // namespace mococrw
