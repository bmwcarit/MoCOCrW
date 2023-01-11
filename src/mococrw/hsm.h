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
class ECCSpec;
class RSASpec;
/**
 * The highest-level abstract class of a Hardware Security Module (HSM).
 *
 * All HSM implementations should inherit this class either directly or
 * indirectly.
 */
class HSM
{
public:
    virtual ~HSM() = default;

    // Many of protected functions provided by the HSM class are seen
    // as internal, not to be used by the User of MoCOCrW but specific
    // friends:
    friend class AsymmetricPublicKey;
    friend class AsymmetricKeypair;

protected:
    /**
     *  Loads public key from HSM.
     *
     *  @param keyID The ID of the public key to load.
     */
    virtual openssl::SSL_EVP_PKEY_Ptr loadPublicKey(const std::string &keyID) const = 0;

    /**
     * Loads private key from HSM.
     *
     * @param keyID The ID of the private key to load.
     */
    virtual openssl::SSL_EVP_PKEY_Ptr loadPrivateKey(const std::string &keyID) const = 0;

    /**
     * @brief Generate a RSA key pair on the HSM
     *
     * @param spec The RSA specification @ref RSASpec
     */
    virtual openssl::SSL_EVP_PKEY_Ptr generateKey(const RSASpec &spec,
                                                  const std::string &keyID,
                                                  const std::string &keyLabel) = 0;

    /**
     * @brief Generate a ECC key pair on the HSM
     *
     * @param spec The ECC specification @ref ECCSpec
     */
    virtual openssl::SSL_EVP_PKEY_Ptr generateKey(const ECCSpec &spec,
                                                  const std::string &keyID,
                                                  const std::string &keyLabel) = 0;
};

/**
 * Hsm handling that leverages OpenSSL's ENGINE_* API interface.
 */
class HsmEngine : public HSM
{
public:
    /**
     * @note Each HsmEngine object is associated with a specific token and a pin to login to that
     * token
     */
    HsmEngine(const std::string &id,
              const std::string &modulePath,
              const std::string &tokenLabel,
              const std::string &pin);
    virtual ~HsmEngine();

protected:
    /** Pointer to OpenSSL ENGINE. */
    openssl::SSL_ENGINE_Ptr _engine;
    /** Engine ID. */
    const std::string _id;
    /** Path to Module. */
    const std::string _modulePath;
    /** Token label used to uniquely identify a token on which objects reside */
    const std::string _tokenLabel;
    /** Pin to access PKCS11 Engine. */
    const std::string _pin;

    openssl::SSL_EVP_PKEY_Ptr loadPublicKey(const std::string &keyID) const override;

    openssl::SSL_EVP_PKEY_Ptr loadPrivateKey(const std::string &keyID) const override;

    openssl::SSL_EVP_PKEY_Ptr generateKey(const RSASpec &spec,
                                          const std::string &keyID,
                                          const std::string &keyLabel) override;

    openssl::SSL_EVP_PKEY_Ptr generateKey(const ECCSpec &spec,
                                          const std::string &keyID,
                                          const std::string &keyLabel) override;
};

}  // namespace mococrw
