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
#include "openssl_wrap.h"

namespace mococrw
{

/* IMPORTANT NOTE:
 * The key classes and infrastracture is build with the idea of immutable
 * key objects in mind. If this ever changes, you need to implement a proper
 * copy constructor that actually provides copies instead of just copying
 * the shared pointer
 */
class AsymmetricKey
{
public:
    class Spec;

    /**
     * Constructs a wrapper object for OpenSSL EVP_PKEY objects
     */
    AsymmetricKey(openssl::SSL_EVP_PKEY_SharedPtr keypair) : _key{std::move(keypair)}
    {
    }

    /**
     * Supported asymmetric key types.
     */
    enum class KeyTypes : int { RSA = EVP_PKEY_RSA, ECC = EVP_PKEY_EC };

    KeyTypes getType() const  { return static_cast<KeyTypes>(openssl::_EVP_PKEY_type(_key.get())); }

    int getKeySize() const { return EVP_PKEY_bits(_key.get());}

    std::unique_ptr<Spec> getKeySpec() const;

    inline const openssl::SSL_EVP_PKEY_SharedPtr& internal() const { return _key; }
    inline openssl::SSL_EVP_PKEY_SharedPtr& internal() { return _key; }
private:
    openssl::SSL_EVP_PKEY_SharedPtr _key;
};

class AsymmetricPublicKey
{
public:
    /*
     * Construct an asymmetric public key from an already existing
     * openssl EVP_PKEY structure.
     *
     * @param key A smart pointer to the EVP_PKEY. Must not be nullptr.
     */
    AsymmetricPublicKey(openssl::SSL_EVP_PKEY_SharedPtr key) : _key{std::move(key)}
    {
    }

    /**
     * Converts the asymmetric public key to the PKCS8 format that can be written in a PEM file.
     * @return public key in PKCS format
     * @throws This method may throw an OpenSSLException if OpenSSL indicates an error
     */
    std::string publicKeyToPem() const;
    /**
     * Reads an asymmetric public key from a PEM string and creates an @ref AsymmetricPublicKey
     * object. Can be considered a factory method for the class.
     * @param pem string to be read.
     * @return the AsymmetricPublicKey object created form the PEM string
     * @throws This method may throw an OpenSSLException if OpenSSL indicates an error
     */
    static AsymmetricPublicKey readPublicKeyFromPEM(const std::string& pem);

    /**
     * Getters for the internal openSSL object.
     */
    inline EVP_PKEY* internal() { return _key.internal().get(); }
    inline const EVP_PKEY* internal() const { return _key.internal().get(); }

    /**
     * Gets the type of the asymmetric key or key pair, @see AsymmetricKey::KeyTypes for the
     * supported types.
     * @return the type of the asymmetric key.
     * @throws This method may throw an OpenSSLException if OpenSSL indicates an error
     */
    AsymmetricKey::KeyTypes getType() const  { return _key.getType(); }

    /**
     * Gets the specification of the asymmetric key in usage
     *
     * @return the specification of the key in use.
     * @throws This method may throw an OpenSSLException if OpenSSL indicates an error
     */
    std::unique_ptr<AsymmetricKey::Spec> getKeySpec() const  { return _key.getKeySpec(); }

    /**
     * Gets the size of the Asymmetric key in bits
     * @return the size of the key in bits
     */
    int getKeySize() const { return _key.getKeySize();}

    inline bool operator==(const AsymmetricPublicKey &rhs) const {
        return openssl::_EVP_PKEY_cmp(internal(), rhs.internal());
    }
    inline bool operator!=(const AsymmetricPublicKey &rhs) const {
        return !(*this == rhs);
    }

protected:
    AsymmetricPublicKey(AsymmetricKey &&key) : _key{std::move(key)}
    {
    }

    AsymmetricKey _key;
};

/**
 *
 * NOTE: This class is the equivalent of a private key,
 * because private keys always hold the corresponding
 * public keys, whereas public keys really only contain
 * the public key.
 */
class AsymmetricKeypair : public AsymmetricPublicKey
{
public:
    /*
     * Construct an asymmetric key pair from an already existing
     * openssl EVP_PKEY structure.
     *
     * @param key A smart pointer to the EVP_PKEY. Must not be nullptr.
     */
    AsymmetricKeypair(openssl::SSL_EVP_PKEY_SharedPtr keypair)
                                : AsymmetricPublicKey{std::move(keypair)}
    {
    }

    /**
     * Generate a RSA asymmetric keypair with default Spec.
     *
     * Currently, a default-spec is an RSASpec with 2048
     * bit modulus. (@see RSASpec)
     *
     * @throws This method may throw an OpenSSLException if OpenSSL
     *      indicates an error
     */
    [[deprecated("Replaced by generateRSA for improved clarity")]]
    static AsymmetricKeypair generate();

    /**
     * Generate an asymmetric keypair with given Spec.
     *
     * @see RSASpec
     * @see ECCSpec
     *
     * @throws This method may throw an OpenSSLException if OpenSSL
     *      indicates an error
     */
    static AsymmetricKeypair generate(const AsymmetricKey::Spec&);

    /**
     * Generate a RSA asymmetric keypair with default Spec.
     *
     * Currently, a default-spec is an RSASpec with 2048
     * bit modulus. (@see RSASpec)
     *
     * @throws This method may throw an OpenSSLException if OpenSSL
     *      indicates an error
     */
    static AsymmetricKeypair generateRSA();

    /**
     * Generate an ECC asymmetric keypair with default Spec.
     *
     * Currently, a default-spec is an ECCspec with a PRIME_256v1 curve
     * (aka NIST P-256 or secp256r1).
     *
     * @throws This method may throw an OpenSSLException if OpenSSL
     *      indicates an error
     */
    static AsymmetricKeypair generateECC();

    /**
     * Serialize the asymmetric keypair encrypted with the given password.
     * The output format is a PEM encoded PKCS8 private key encrypted with
     * AES-256-CBC.
     *
     * If the password is empty, the serialized key is unencrypted.
     *
     * @param pwd The password that should be used for encryption. No encryption
     *            if pwd is the empty string.
     * @return PEM encoded PKCS8 serialized private key.
     * @throw OpenSSLException if OpenSSL indicates an error during the serialization
     *                         procedure
     */
    std::string privateKeyToPem(const std::string& pwd) const;

    static AsymmetricKeypair readPrivateKeyFromPEM(const std::string& pem, const std::string& password);

private:
    AsymmetricKeypair(AsymmetricKey &&key) : AsymmetricPublicKey{std::move(key)}
    {
    }
};

/**
 * For readability, this alias may sometime prove useful.
 */
using AsymmetricPrivateKey = AsymmetricKeypair;

class AsymmetricKey::Spec
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
    virtual AsymmetricKey generate() const = 0;
};
/**
 * RSA specification used to hold the necessary parameters to generate a RSA key pair.
 */
class RSASpec final : public AsymmetricKey::Spec
{
public:
    /**
     * Default RSA key size in case none is specified by the used
     */
    static constexpr unsigned int defaultSize = 2048;
    explicit RSASpec(unsigned int numBits) : _numBits{numBits} {}
    RSASpec() : RSASpec{defaultSize} {}
    AsymmetricKey generate() const override;
    inline unsigned int numberOfBits() const { return _numBits; }
private:
    unsigned int _numBits;
};

/**
 * ECC specification used to hold the necessary parameters to generate a ECC key pair.
 */
class ECCSpec final : public AsymmetricKey::Spec
{
public:
    /**
     * Default elliptic curve to be used in case none is specified by the user.
     */
    static constexpr openssl::ellipticCurveNid defaultCurveNid = openssl::ellipticCurveNid::PRIME_256v1;
    explicit ECCSpec(openssl::ellipticCurveNid curveNid) : _curveNid{curveNid} {}
    ECCSpec() : ECCSpec{defaultCurveNid} {}
    inline openssl::ellipticCurveNid curve() const { return _curveNid; }
    AsymmetricKey generate() const override;
private:
    openssl::ellipticCurveNid _curveNid;
};

}
