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
    virtual openssl::SSL_EVP_PKEY_Ptr loadPublicKey(const std::string &keyID) = 0;

    /**
     * Loads private key from HSM.
     *
     * @param keyID The ID of the private key to load.
     */
    virtual openssl::SSL_EVP_PKEY_Ptr loadPrivateKey(const std::string &keyID) = 0;

    /**
     * @brief Generate a key pair in the HSM, return the public key
     *
     * @param spec The RSA specification, which shall be used for key generation
     * @param keyID The key identifier
     * @param tokenLabel The token label
     * @param keyLabel The key label
     * @return openssl::SSL_EVP_PKEY_Ptr
     */
    virtual openssl::SSL_EVP_PKEY_Ptr genKeyGetPublic(const RSASpec &spec,
                                                      const std::string &keyID,
                                                      const std::string &tokenLabel,
                                                      const std::string &keyLabel) = 0;
    /**
     * @brief Overloaded for ECC specs
     */
    virtual openssl::SSL_EVP_PKEY_Ptr genKeyGetPublic(const ECCSpec &spec,
                                                      const std::string &keyID,
                                                      const std::string &tokenLabel,
                                                      const std::string &keyLabel) = 0;

    /**
     * @brief Generate a key pair in the HSM, return the private key
     *
     * @param spec The RSA specification, which shall be used for key generation
     * @param keyID The key identifier
     * @param tokenLabel The token label
     * @param keyLabel The key label
     * @return openssl::SSL_EVP_PKEY_Ptr
     */
    virtual openssl::SSL_EVP_PKEY_Ptr genKeyGetPrivate(const RSASpec &spec,
                                                       const std::string &keyID,
                                                       const std::string &tokenLabel,
                                                       const std::string &keyLabel) = 0;

    /**
     * @brief Overloaded for ECC specs
     */
    virtual openssl::SSL_EVP_PKEY_Ptr genKeyGetPrivate(const ECCSpec &spec,
                                                       const std::string &keyID,
                                                       const std::string &tokenLabel,
                                                       const std::string &keyLabel) = 0;

    virtual void genKey(const RSASpec &spec,
                        const std::string &keyID,
                        const std::string &tokenLabel,
                        const std::string &keyLabel) = 0;

    virtual void genKey(const ECCSpec &spec,
                        const std::string &keyID,
                        const std::string &tokenLabel,
                        const std::string &keyLabel) = 0;
};

/**
 * Abstract class of an HSMEngine that leverages OpenSSL's ENGINE_* API interface.
 */
class HsmEngine : public HSM
{
public:
    HsmEngine(const std::string &id, const std::string &modulePath, const std::string &pin);
    virtual ~HsmEngine();

protected:
    /** Pointer to OpenSSL ENGINE. */
    openssl::SSL_ENGINE_Ptr _engine;
    /** Engine ID. */
    const std::string _id;
    /** Path to Module. */
    const std::string _modulePath;
    /** Pin to access PKCS11 Engine. */
    const std::string _pin;

    openssl::SSL_EVP_PKEY_Ptr loadPublicKey(const std::string &keyID) override;

    openssl::SSL_EVP_PKEY_Ptr loadPrivateKey(const std::string &keyID) override;

    openssl::SSL_EVP_PKEY_Ptr genKeyGetPublic(const RSASpec &spec,
                                              const std::string &keyID,
                                              const std::string &tokenLabel,
                                              const std::string &keyLabel) override;

    openssl::SSL_EVP_PKEY_Ptr genKeyGetPublic(const ECCSpec &spec,
                                              const std::string &keyID,
                                              const std::string &tokenLabel,
                                              const std::string &keyLabel) override;

    openssl::SSL_EVP_PKEY_Ptr genKeyGetPrivate(const RSASpec &spec,
                                               const std::string &keyID,
                                               const std::string &tokenLabel,
                                               const std::string &keyLabel) override;

    openssl::SSL_EVP_PKEY_Ptr genKeyGetPrivate(const ECCSpec &spec,
                                               const std::string &keyID,
                                               const std::string &tokenLabel,
                                               const std::string &keyLabel) override;

    void genKey(const RSASpec &spec,
                const std::string &keyID,
                const std::string &tokenLabel,
                const std::string &keyLabel) override;

    void genKey(const ECCSpec &spec,
                const std::string &keyID,
                const std::string &tokenLabel,
                const std::string &keyLabel) override;
};

}  // namespace mococrw
