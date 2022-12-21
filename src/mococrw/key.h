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
#ifdef HSM_ENABLED
#include "mococrw/hsm.h"
#endif
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
    AsymmetricKey(openssl::SSL_EVP_PKEY_SharedPtr keypair) : _key{std::move(keypair)} {}

    /**
     * Supported asymmetric key types.
     */
    enum class KeyTypes : int { RSA, ECC, ECC_ED };

    KeyTypes getType() const;

    int getKeySize() const { return EVP_PKEY_bits(_key.get()); }

    std::unique_ptr<Spec> getKeySpec() const;

    inline const openssl::SSL_EVP_PKEY_SharedPtr &internal() const { return _key; }
    inline openssl::SSL_EVP_PKEY_SharedPtr &internal() { return _key; }

private:
    openssl::SSL_EVP_PKEY_SharedPtr _key;
};

class ECCSpec;

class AsymmetricPublicKey
{
public:
    /*
     * Construct an asymmetric public key from an already existing
     * openssl EVP_PKEY structure.
     *
     * @param key A smart pointer to the EVP_PKEY. Must not be nullptr.
     */
    AsymmetricPublicKey(openssl::SSL_EVP_PKEY_SharedPtr key) : _key{std::move(key)} {}

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
    static AsymmetricPublicKey readPublicKeyFromPEM(const std::string &pem);

#ifdef HSM_ENABLED
    /**
     * Loads a public key from an HSM, creating an @ref AsymmetricPublicKey
     * object as a result.
     */
    static AsymmetricPublicKey readPublicKeyFromHSM(const HSM &hsm, const std::string &keyID);
#endif

    /**
     * @brief Returns a public key object based on the provided EC point
     *
     * This function creates a key object based on the point(s) in octet form and the elliptic curve
     * group given by keySpec. The leading byte with the point conversion form identifier (0x02 or
     * 0x03 for compressed, 0x04 for uncompressed, 0x06 or 0x07 for hybrid points) has to be in
     * place.
     *
     * Remark: Ed-Curves (Ed448, Ed25519) are currently not supported. If you use one of these
     * curves a MoCOCrWException is thrown.
     * @throws MoCOCrWException if the given spec is not a elliptic curve spec or an Ed-spec
     * @param keySpec The key specification for creating the key
     * @param point The point(s) representing the public key
     * @return An asymmetric public key
     */
    static AsymmetricPublicKey fromECPoint(const std::shared_ptr<ECCSpec> keySpec,
                                           const std::vector<uint8_t> &point);

    /**
     * @brief This returns the point(s) of the current AsymmetricPublicKey in octet representation.
     *
     * Depending on the conversion form the correct identifier will be prepended to the actual point
     * (0x02 or 0x03 for compressed form, 0x04 for uncompressed form. 0x06 or 0x07 for hybrid form).
     *
     * Remark: Ed-Curves (Ed448, Ed25519) are currently not supported. If you use one of these
     * curves a MoCOCrWException is thrown.
     * @throws MoCOCrWException if the given key is not a elliptic curve key or an Ed-key
     * @param form The transformation form.
     * @return The octet representation of the public key. The form of the point is defined by the
     * argument form.
     */
    std::vector<uint8_t> toECPoint(openssl::EllipticCurvePointConversionForm form);

    /**
     * @brief Get length of the point of the current AsymmetricPublicKey in octet representation
     *
     * Depending on the public key length and the elliptic curve point conversion form, the public
     * key will take different amount of bytes when encoded. This function can be used to
     * conveniently deduct the encoded length while deserializing.
     * @param form Conversion form
     * @return Encoded public key size in bytes
     * @throws MoCOCrWException if the key is not of type AsymmetricKey::KeyTypes::ECC
     */
    size_t getECOctetLength(openssl::EllipticCurvePointConversionForm form);

    /**
     * Getters for the internal openSSL object.
     */
    inline EVP_PKEY *internal() { return _key.internal().get(); }
    inline const EVP_PKEY *internal() const { return _key.internal().get(); }

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
    std::unique_ptr<AsymmetricKey::Spec> getKeySpec() const { return _key.getKeySpec(); }

    /**
     * Gets the size of the Asymmetric key in bits
     * @return the size of the key in bits
     */
    int getKeySize() const { return _key.getKeySize(); }

    inline bool operator==(const AsymmetricPublicKey &rhs) const
    {
        return openssl::_EVP_PKEY_cmp(internal(), rhs.internal());
    }
    inline bool operator!=(const AsymmetricPublicKey &rhs) const { return !(*this == rhs); }

protected:
    AsymmetricPublicKey(AsymmetricKey &&key) : _key{std::move(key)} {}

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
    [[deprecated("Replaced by generateRSA for improved clarity")]] static AsymmetricKeypair
    generate();

    /**
     * Generate an asymmetric keypair with given Spec.
     *
     * @see RSASpec
     * @see ECCSpec
     *
     * @throws This method may throw an OpenSSLException if OpenSSL
     *      indicates an error
     */
    static AsymmetricKeypair generate(const AsymmetricKey::Spec &);

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
    static AsymmetricKeypair generateEd448();
    static AsymmetricKeypair generateEd25519();

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
    std::string privateKeyToPem(const std::string &pwd) const;

    static AsymmetricKeypair readPrivateKeyFromPEM(const std::string &pem,
                                                   const std::string &password);

#ifdef HSM_ENABLED
    /**
     * Loads a private key from an HSM, creating an @ref AsymmetricPublicKey
     * object as a result.
     */
    static AsymmetricKeypair readPrivateKeyFromHSM(const HSM &hsm, const std::string &keyID);

    /**
     * @brief Generates RSA keypair on HSM token according to the spec given. The keys are fetched
     * _only_ by key ID so generating multiple keys with the same ID must be avoided!
     * @param hsm Initialized HSM engine handle
     * @param spec @ref RSASpec
     * @param keyID ID of the key on HSM. We use IDs to fetch keys from HSM. _Only_ hex values are
     * valid! Generating 2 keys with the same ID must be avoided. This is not prohibited by PKCS#11
     * standard but since we currently only fetch by key ID, there is no way of ensuring that the
     * correct key is fetched.
     * @param tokenLabel Label of the token on HSM. This determines where they key shall be stored.
     * @param keyLabel Arbitrary key label
     * @return AsymmetricKeypair @ref AsymmetricKeypair
     * @throw MoCOCrWException Since most of the logic is happening outside of OpenSSL and inside
     * libp11 and HSM module implementation, exception's what() tries to list the most common things
     * that could go wrong. libp11 does log some things to stderr, check if there's more context
     * there
     */
    static AsymmetricKeypair generateKeyOnHsm(const HSM &hsm,
                                              const RSASpec &spec,
                                              const std::string &keyID,
                                              const std::string &tokenLabel,
                                              const std::string &keyLabel);

    /**
     * @brief Generates ECC keypair on HSM token according to the spec given. The keys are fetched
     * _only_ by key ID so generating multiple keys with the same ID must be avoided!
     * @param hsm Initialized HSM engine handle
     * @param spec @ref ECCSpec
     * @param keyID ID of the key on HSM. We use IDs to fetch keys from HSM. _Only_ hex values are
     * valid! Generating 2 keys with the same ID must be avoided. This is not prohibited by PKCS#11
     * standard but since we currently only fetch by key ID, there is no way of ensuring that the
     * correct key is fetched.
     * @param tokenLabel Label of the token on HSM. This determines where they key shall be stored.
     * @param keyLabel Arbitrary key label
     * @return AsymmetricKeypair @ref AsymmetricKeypair
     * @throw MoCOCrWException Since most of the logic is happening outside of OpenSSL and inside
     * libp11 and HSM module implementation, exception's what() tries to list the most common things
     * that could go wrong. libp11 does log some things to stderr, check if there's more context
     * there
     */
    static AsymmetricKeypair generateKeyOnHsm(const HSM &hsm,
                                              const ECCSpec &spec,
                                              const std::string &keyID,
                                              const std::string &tokenLabel,
                                              const std::string &keyLabel);
#endif

private:
    AsymmetricKeypair(AsymmetricKey &&key) : AsymmetricPublicKey{std::move(key)} {}
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
    static constexpr openssl::ellipticCurveNid defaultCurveNid =
            openssl::ellipticCurveNid::PRIME_256v1;
    explicit ECCSpec(openssl::ellipticCurveNid curveNid) : _curveNid{curveNid} {}
    ECCSpec() : ECCSpec{defaultCurveNid} {}
    inline openssl::ellipticCurveNid curve() const { return _curveNid; }
    inline std::string curveName() const { return openssl::_EC_curve_nid2nist(int(_curveNid)); }
    AsymmetricKey generate() const override;

private:
    openssl::ellipticCurveNid _curveNid;
};

}  // namespace mococrw
