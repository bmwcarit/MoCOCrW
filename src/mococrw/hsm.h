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
#pragma once

#include "openssl_wrap.h"

namespace mococrw
{
/**
 * The highest-level abstract class of a Hardware Security Module (HSM).
 *
 * All HSM implementations should inherit this class either directly or
 * indirectly.
 */
class HSM
{
public:
    HSM(const std::string &name) : _name(name) {}
    virtual ~HSM() = default;

    /**
     * Returns the name of the HSM.
     */
    const std::string &getName();

protected:
    const std::string &_name;

    /**
     *  Loads public key from HSM.
     *
     *  @param keyID The ID of the public key to load.
     */
    virtual openssl::SSL_EVP_PKEY_Ptr loadPublicKey(const std::string &keyID) = 0;

    /**
     * Stores public key to HSM.
     *
     * @param key The public key to store.
     * @param label The label of the key to store.
     * @param keyID The ID of the key to store.
     */
    virtual void storePublicKey(EVP_PKEY *key,
                                const std::string &label,
                                const std::string &keyID) = 0;

    /**
     * Loads private key from HSM.
     *
     * @param keyID The ID of the private key to load.
     */
    virtual openssl::SSL_EVP_PKEY_Ptr loadPrivateKey(const std::string &keyID) = 0;

    /**
     * Stores private key to HSM.
     *
     * @param key The private key to store.
     * @param label The label of the key to store.
     * @param keyID The ID of the key to store.
     */
    virtual void storePrivateKey(EVP_PKEY *key,
                                 const std::string &label,
                                 const std::string &keyID) = 0;

    /**
     * Generates a key pair via HSM.
     *
     * @param bits Specifies key size.
     * @param label The label of the key to generate.
     * @param id The ID of the key to generate.
     *
     * \note Currently, RSA keys are only supported.
     */
    virtual void generateKey(unsigned int bits,
                             const std::string &label,
                             const std::string &id) = 0;
};

/**
 * Abstract class of an HSMEngine that leverages OpenSSL's ENGINE_* API interface.
 */
class HsmEngine : public HSM
{
public:
    HsmEngine(const std::string &name,
              const std::string &id,
              const std::string &modulePath,
              const std::string &pin);
    virtual ~HsmEngine();

protected:
    /** Pointer to OpenSSL ENGINE. */
    openssl::SSL_ENGINE_Ptr _engine;
    /** Engine ID. */
    const std::string &_id;
    /** Path to Module. */
    const std::string &_modulePath;
    /** Pin to access PKCS11 Engine. */
    const std::string &_pin;

    openssl::SSL_EVP_PKEY_Ptr loadPublicKey(const std::string &keyID) override;

    openssl::SSL_EVP_PKEY_Ptr loadPrivateKey(const std::string &keyID) override;
};

}  // namespace mococrw
