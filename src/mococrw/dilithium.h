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

#include <cstdint>
#include <memory>
#include <vector>
#include "mococrw/asymmetric_crypto_ctx.h"
#include "mococrw/key.h"

namespace mococrw
{
/*
 * The idea is to implement dilithium in a way that we can later alias the classes here to the ones
 * in key.h and asymmetric_crypto_ctx.h with reduced efforts in code adaptions.
 */

/**
 * This class is a replacement of EVP_PKEY as long as dilithium is not supported by the openssl
 * version used by MoCOCrW. It stores the key as std::vector<uint8_t> and the key type.
 * Addittionally some convenient functions are added.
 */
class DilithiumKeyImpl
{
public:
    enum class DilithiumParameterSet : int { DILITHIUM2, DILITHIUM3, DILITHIUM5 };

    DilithiumKeyImpl(const std::vector<uint8_t> key_data,
                     DilithiumKeyImpl::DilithiumParameterSet paramSet,
                     bool is_private_key)
            : _key_data{std::move(key_data)}, _is_private_key(is_private_key), _paramSet(paramSet)
    {
        if (!hasValidKeySize()) {
            throw MoCOCrWException("Key data does not match the expected size.");
        }
    }

    /**
     * @brief Parses a ASN.1 X509 public key object (see RFC5280)
     *
     * @param x509PubKey The public key object as defined in RFC5280
     * @return A shared pointer to a dilithium implementation object
     */
    static std::shared_ptr<DilithiumKeyImpl> readPublicKeyFromDER(
            const std::vector<uint8_t> &x509PubKey);

    /**
     * @brief Parses a ASN.1 PKCS#8 private key object (see RFC5208)
     *
     * @param x509PubKey The private key object as defined in RFC5208
     * @return A shared pointer to a dilithium implementation object
     */
    static std::shared_ptr<DilithiumKeyImpl> readPrivateKeyFromDER(
            const std::vector<uint8_t> &pkcs8PrivKey);

    /**
     * @returns The key type
     */
    AsymmetricKey::KeyTypes getType() const { return _keyType; };

    /**
     * @returns The size of the raw key data
     */
    uint getKeySize() const { return _key_data.size(); }

    /**
     * Returns the raw key data
     *
     * @returns The raw key data
     */
    const std::vector<uint8_t> getKeyData() const { return _key_data; };

    /**
     * Returns the public key. If a private key is stored the public key is extracted and returned
     *
     * @return The public key
     * @throws If the stored key size doesn't match the size of a private or public key
     * @throws If the extraction function to get the public key from a private key returns an error
     * @throws If the key type is not supported
     */
    DilithiumKeyImpl getPublicKey() const;

    /**
     * @brief Checks if the key has a valid key size
     *
     * @return true if the key matches either the length of the private or public key of the given
     * key type
     * @return false otherwise
     */
    bool hasValidKeySize() const;

    /**
     * Checks if the key size matches the size of a private key. Does not do any validity checks.
     * The key size is dependent on the selected key type (Dilithium3 or Dilithium5).
     *
     * @return True if the key size matches the size of private keys.
     * @throws If the key size neither matches a private or public key size.
     * @throws if the key type is not supported
     */
    bool isPrivateKey() const;

    /**
     * @brief Get the selected dilithium parameter set (one of DILITHIUM{2,3,5})
     *
     * @return The parameter set chosen
     */
    DilithiumParameterSet getDilithiumParameterSet() const { return _paramSet; }

    inline bool operator==(const DilithiumKeyImpl &rhs) const
    {
        return _key_data == rhs.getKeyData() && _is_private_key == rhs.isPrivateKey() &&
               _paramSet == rhs.getDilithiumParameterSet();
    }

private:
    const AsymmetricKey::KeyTypes _keyType = AsymmetricKey::KeyTypes::DILITHIUM;
    const std::vector<uint8_t> _key_data;
    const bool _is_private_key;
    const DilithiumParameterSet _paramSet;
};

/**
 * @brief Dilithium representation of AsymmetricKey
 *
 * @see AsymmetricKey
 *
 * This shall be replaced by AsymmetricKey once Dilithium is supported by the openssl version
 * used by MoCOCrW.
 * The interface is similar to the one of AsymmetricKey.
 *
 * For documentation see AsymmetricKey
 */
class DilithiumAsymmetricKey
{
public:
    class Spec;
    DilithiumAsymmetricKey(std::shared_ptr<DilithiumKeyImpl> keyData) : _key{std::move(keyData)} {}

    AsymmetricKey::KeyTypes getType() const { return _key->getType(); }

    int getKeySize() const noexcept;

    std::unique_ptr<Spec> getKeySpec() const;

    inline const std::shared_ptr<const DilithiumKeyImpl> _internal() const { return _key; }
    inline std::shared_ptr<DilithiumKeyImpl> _internal() { return _key; }

private:
    std::shared_ptr<DilithiumKeyImpl> _key;
};

/**
 * @brief Dilithium representation of AsymmetricPublicKey
 *
 * @see AsymmetricPublicKey
 *
 * This shall be replaced by AsymmetricPublicKey once Dilithium is supported by the openssl version
 * used by MoCOCrW.
 * The interface is similar to the one of AsymmetricPublicKey.
 *
 * For documentation see AsymmetricPublicKey
 */
class DilithiumAsymmetricPublicKey
{
public:
    DilithiumAsymmetricPublicKey(std::shared_ptr<DilithiumKeyImpl> key) : _key{std::move(key)} {}

    /**
     * @brief Parses an ASN.1 struct in DER format at returns a public key object
     *
     * @param asn1Data The ASN.1 struct in DER format
     * @return the DilithiumAsymmetricPublicKey object created form the DER data
     * @throws MoCOCrWException if the struct cannot be parsed or if the key is invalid
     */
    static DilithiumAsymmetricPublicKey readPublicKeyfromDER(const std::vector<uint8_t> &asn1Data);

    /**
     * Getters for the internal dilithium implementation objet.
     */
    inline DilithiumKeyImpl *internal() { return _key._internal().get(); }
    inline const DilithiumKeyImpl *_internal() const { return _key._internal().get(); }

    /**
     * Gets the type of the asymmetric key or key pair, @see AsymmetricKey::KeyTypes for the
     * supported types.
     * @return the type of the asymmetric key.
     * @throws This method may throw an OpenSSLException if OpenSSL indicates an error
     */
    AsymmetricKey::KeyTypes getType() const { return _key.getType(); }

    /**
     * Gets the specification of the asymmetric key in usage
     *
     * @return the specification of the key in use.
     * @throws This method may throw an OpenSSLException if OpenSSL indicates an error
     */
    std::unique_ptr<DilithiumAsymmetricKey::Spec> getKeySpec() const { return _key.getKeySpec(); }

    /**
     * Gets the size of the Asymmetric key in bits
     * @return the size of the key in bits
     */
    int getKeySize() const { return _key.getKeySize(); }

    inline bool operator==(const DilithiumAsymmetricPublicKey &rhs) const
    {
        return *_internal() == *rhs._internal();
    }
    inline bool operator!=(const DilithiumAsymmetricPublicKey &rhs) const
    {
        return !(*this == rhs);
    }

protected:
    DilithiumAsymmetricPublicKey(DilithiumAsymmetricKey &&key) : _key{std::move(key)} {}

    DilithiumAsymmetricKey _key;
};

/**
 * @brief Dilithium representation of AsymmetricKeypair
 *
 * @see AsymmetricKeypair
 *
 * This shall be replaced by AsymmetricKeypair once Dilithium is supported by the openssl version
 * used by MoCOCrW.
 * The interface is similar to the one of AsymmetricKeypair.
 *
 * For documentation see AsymmetricKeypair
 */
class DilithiumAsymmetricKeypair : public DilithiumAsymmetricPublicKey
{
public:
    DilithiumAsymmetricKeypair(std::shared_ptr<DilithiumKeyImpl> keypair)
            : DilithiumAsymmetricPublicKey{std::move(keypair)}
    {
    }

    /**
     * @brief Parses an ASN.1 struct in DER format at returns a private key object
     *
     * @param asn1Data The ASN.1 struct in DER format
     * @return the DilithiumAsymmetricKeypair object created form the DER data
     * @throws MoCOCrWException if the struct cannot be parsed or if the key is invalid
     */
    static DilithiumAsymmetricKeypair readPrivateKeyfromDER(const std::vector<uint8_t> &asn1Data);

    /**
     * Generate an asymmetric keypair with given Spec.
     *
     * @see DilithiumSpec
     *
     * @throws This method may throw an OpenSSLException if OpenSSL
     *      indicates an error
     */
    static DilithiumAsymmetricKeypair generate(const DilithiumAsymmetricKey::Spec &spec);

private:
    DilithiumAsymmetricKeypair(DilithiumAsymmetricKey &&key)
            : DilithiumAsymmetricPublicKey{std::move(key)}
    {
    }
};

/**
 * For readability, this alias may sometime prove useful.
 */
using DilithiumAsymmetricPrivateKey = DilithiumAsymmetricKeypair;

/**
 * @brief Specification class for Dilithium keys (clone of AsymmetricKey::Spec)
 *
 * @see AsymmetricKey::Spec for mor information
 *
 */
class DilithiumAsymmetricKey::Spec
{
public:
    virtual ~Spec() = default;

    /**
     * Generate an AsymmetricKey from this
     * spec instance.
     *
     * Implementations should override this method
     * to encapsulate the specifics of how to generate
     * the various types of keys (RSA and ECC).
     *
     */
    virtual DilithiumAsymmetricKey generate() const = 0;
};

/**
 * @brief Specification for Dilithium keys
 *
 * This class allows to generate Dilithium keypairs.
 *
 */
class DilithiumSpec final : public DilithiumAsymmetricKey::Spec
{
public:
    /* According to https://pq-crystals.org/dilithium/ DILITHIUM3 shall be used
     * as default parameter set.
     */
    static const DilithiumKeyImpl::DilithiumParameterSet defaultDilithiumParamSet =
            DilithiumKeyImpl::DilithiumParameterSet::DILITHIUM3;

    explicit DilithiumSpec(DilithiumKeyImpl::DilithiumParameterSet paramSet) : _paramSet{paramSet}
    {
    }

    DilithiumSpec() : DilithiumSpec{defaultDilithiumParamSet} {}
    DilithiumAsymmetricKey generate() const;

private:
    DilithiumKeyImpl::DilithiumParameterSet _paramSet;
};

class DilithiumSigningCtx : public MessageSignatureCtx
{
public:
    DilithiumSigningCtx(const DilithiumAsymmetricPrivateKey &key);

    ~DilithiumSigningCtx();
    /**
     * @brief Copy Constructor
     */
    DilithiumSigningCtx(const DilithiumSigningCtx &other);

    /**
     * @brief Copy Assignment
     */
    DilithiumSigningCtx &operator=(const DilithiumSigningCtx &other);

    std::vector<uint8_t> signMessage(const std::vector<uint8_t> &message);

private:
    /**
     * Internal class for applying the PIMPL design pattern
     * (to hide the details of storing the padding objects from the client)
     */
    class Impl;

    /**
     * Pointer for PIMPL design pattern
     */
    std::unique_ptr<Impl> _impl;
};

class DilithiumVerificationCtx : public MessageVerificationCtx
{
public:
    DilithiumVerificationCtx(const DilithiumAsymmetricPublicKey &key);
    ~DilithiumVerificationCtx();
    /**
     * @brief Copy Constructor
     */
    DilithiumVerificationCtx(const DilithiumVerificationCtx &other);

    /**
     * @brief Copy Assignment
     */
    DilithiumVerificationCtx &operator=(const DilithiumVerificationCtx &other);

    void verifyMessage(const std::vector<uint8_t> &signature, const std::vector<uint8_t> &message);

private:
    /**
     * Internal class for applying the PIMPL design pattern
     * (to hide the details of storing the padding objects from the client)
     */
    class Impl;

    /**
     * Pointer for PIMPL design pattern
     */
    std::unique_ptr<Impl> _impl;
};

}  // namespace mococrw