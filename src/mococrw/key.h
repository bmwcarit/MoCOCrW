/**
 * @file
 * @copyright (C) 2017, BMW AG
 * @copyright (C) 2017, BMW Car IT GmbH
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

/*
 * If we support more than RSA keys at some point, this will become necessary
 * When that happens, we will also need to expose these paramters via the Spec class
 */
#if 0
    enum class Types : int { RSA = EVP_PKEY_RSA, };

    Types getType() const  { return reinterpret_cast<Types>(EVP_PKEY_type(_key.get()->type)); }
private:
    //note that this unique_ptr will not compile because of the incompleteness of type Spec, but
    //this is just to hint at what is to come
    std::unique_ptr<Spec> _spec = nullptr;

    //this we then want to call from the constructor
    void _createSpecFromPKEY() { switch(getType()) .... }

#endif

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

    std::string publicKeyToPem() const;
    static AsymmetricPublicKey readPublicKeyFromPEM(const std::string& pem);

    inline EVP_PKEY* internal() { return _key.internal().get(); }
    inline const EVP_PKEY* internal() const { return _key.internal().get(); }

    inline bool operator==(const AsymmetricPublicKey &rhs) const
    {
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
 * pulbic keys, whereas public keys really only contain
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
     * Generate an asymmetric keypair with default Spec.
     *
     * Currently, a default-spec is an RSASpec with 2048
     * bit modulus. (@see RSASpec)
     *
     * @throws This method may throw an OpenSSLException if OpenSSL
     *      indicates an error
     */
    static AsymmetricKeypair generate();

    /**
     * Generate an asymmetric keypair with given Spec.
     *
     * @see RSASpec
     *
     * @throws This method may throw an OpenSSLException if OpenSSL
     *      indicates an error
     */
    static AsymmetricKeypair generate(const AsymmetricKey::Spec&);

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
     * the various types of keys (RSA, DSA, DH).
     *
     */
    virtual AsymmetricKey generate() const = 0;
};

class RSASpec final : public AsymmetricKey::Spec
{
public:
    static constexpr unsigned int defaultSize = 2048;
    explicit RSASpec(unsigned int numBits) : _numBits{numBits} {}
    RSASpec() : RSASpec{defaultSize} {}
    AsymmetricKey generate() const override;
    inline unsigned int numberOfBits() const { return _numBits; }
private:
    unsigned int _numBits;
};
}
