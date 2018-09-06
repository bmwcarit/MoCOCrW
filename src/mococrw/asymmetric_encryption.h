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
#pragma once

#include "key.h"
#include "openssl_wrap.h"
#include "padding_mode.h"

namespace mococrw {

/**
 * This class is used to perform RSA asymmetric encryption and decryption
 */
class AsymmetricEncryption
{
public:
    AsymmetricEncryption() = delete;

    /**
     * @brief CryptoData
     * 
     * This helper class defines the input and output data type used for encryption and decryption.
     * Currently this class abstracts two underlying types (std::string and std::vector<unit_8t>).
     * The user is free to call the encrypt and decrypt functionalities with either of the available
     * underlying types.
     */
    class CryptoData
    {
    public:
        CryptoData() = default;
        CryptoData(const std::string& data);
        CryptoData(const std::vector<uint8_t>& data);

        CryptoData& operator=(const std::vector<uint8_t>& data);
        CryptoData& operator=(const std::string& data);
        friend std::ostream& operator<<(std::ostream& os, const CryptoData& data);

        std::string toString() const;
        std::string toHex() const;
        std::vector<uint8_t> toByteArray() const;

    private:
        std::vector<uint8_t> _data;
    };

public:
    /**
     * @brief Encrypt a message
     *
     * Encrypts the input message based on a given encryption context (RSA key + Padding Mode).
     *
     * @param key RSA public key used to encrypt the message.
     * @param pad Padding mode to be used in the encryption.
     * @param message The message to be encrypted
     * @returns The encrypted message
     * @throw MoCOCrWException if the encryption operation fails.
     */
    static std::vector<uint8_t> encrypt(AsymmetricPublicKey key,
                                        const RSAPadding& pad,
                                        const CryptoData& message);

    /**
     * @brief Decrypt a message
     *
     * Decrypts a ciphered message based on a given decryption (RSA key + Padding Mode).
     *
     * @param key RSA public key used to decrypt the message.
     * @param pad Padding mode to be used in the decryption.
     * @param message The message to be decrypted
     * @returns The decrypted message
     * @throw MoCOCrWException if the decryption fails.
     */
    static CryptoData decrypt(AsymmetricPrivateKey key,
                              const RSAPadding& pad,
                              const std::vector<uint8_t>& message);


private:

    /**
     * Sets specific context configurations when the asymmetric encryption uses the OAEP padding
     * @param oaepPaddingMode OAEP padding mode object
     * @param keyCtx OpennSSL context of the RSA key
     */
    static void configOaepCtx(const OAEPPadding& oaepPaddingMode,
                              openssl::SSL_EVP_PKEY_CTX_Ptr& keyCtx);
};

} // namespace mococrw
