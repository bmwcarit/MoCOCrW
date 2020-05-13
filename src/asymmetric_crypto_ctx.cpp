/*
 * #%L
 * %%
 * Copyright (C) 2018-2020 BMW Car IT GmbH
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

#include <boost/format.hpp>
#include <limits>

#include "mococrw/hash.h"
#include "mococrw/asymmetric_crypto_ctx.h"

namespace mococrw {

    using namespace openssl;

    using SSL_RSA_ENCRYPTION_DATA_Ptr = std::unique_ptr<unsigned char, SSLFree<unsigned char>>;

    using SSL_SIGNATURE_DATA_Ptr = std::unique_ptr<unsigned char, SSLFree<unsigned char>>;


    /* #############
     * #  Helpers  #
     * #############
     */

    /*
     * Creates the digest of the given message using the specified hash function
     */
    std::vector<uint8_t> createHash(openssl::DigestTypes hashFunction,
                                    const std::vector<uint8_t>& message) {
        switch (hashFunction) {
            case openssl::DigestTypes::SHA1:
                return sha1(message);
            case openssl::DigestTypes::SHA256:
                return sha256(message);
            case openssl::DigestTypes::SHA384:
                return sha384(message);
            case openssl::DigestTypes::SHA512:
                return sha512(message);
            case openssl::DigestTypes::SHA3_256:
                return sha3_256(message);
            case openssl::DigestTypes::SHA3_384:
                return sha3_384(message);
            case openssl::DigestTypes::SHA3_512:
                return sha3_512(message);
            default:
                throw MoCOCrWException("Unknown Hash Function");
        };
    }

    /*
     * Performs the signature using the openssl EVP_PKEY_sign interface
     * (common for RSA and ECDSA signatures)
     */
    std::vector<uint8_t> signHelper(SSL_EVP_PKEY_CTX_Ptr& keyCtx,
                                    const std::vector<uint8_t>& toBeSigned) {
        size_t sigLen;
        SSL_SIGNATURE_DATA_Ptr signatureData;

        _EVP_PKEY_sign(keyCtx.get(),
                       nullptr,
                       &sigLen,
                       reinterpret_cast<const unsigned char *>(toBeSigned.data()),
                       toBeSigned.size());

        signatureData.reset(static_cast<unsigned char *>(_OPENSSL_malloc(sigLen)));

        _EVP_PKEY_sign(keyCtx.get(),
                       signatureData.get(),
                       &sigLen,
                       reinterpret_cast<const unsigned char *>(toBeSigned.data()),
                       toBeSigned.size());

        return std::vector<uint8_t>(signatureData.get(), signatureData.get() + sigLen);
    }

    /*
     * Interface Destructors
     */
    EncryptionCtx::~EncryptionCtx() = default;
    DecryptionCtx::~DecryptionCtx() = default;
    DigestSignatureCtx::~DigestSignatureCtx() = default;
    MessageSignatureCtx::~MessageSignatureCtx() = default;
    DigestVerificationCtx::~DigestVerificationCtx() = default;
    MessageVerificationCtx::~MessageVerificationCtx() = default;


    /*
     * Base class for signature contexts that support specifying a hash function
     */
    class SignatureCtxImpl {
    public:
        SignatureCtxImpl(openssl::DigestTypes hashFunction) : hashFunction(hashFunction) {}

        openssl::DigestTypes hashFunction;
    };

    /*
     * ####################
     * #  RSA Encryption  #
     * ####################
     */

    /*
     * Common base class for all PIMPL classes of the RSA contexts
     *
     * Implements the check if the given key is a RSA key in the constructor and enables
     * to call the prepareOpenSSLContext method on the given padding.
     */
    template <class Key, class PaddingBase>
    class RSAImpl {
    public:
        /*
         * Constructor that checks the type of the given key
         */
        RSAImpl(const Key& key, std::shared_ptr<PaddingBase> padding) : key(key), padding(padding) {
            // Not really nice but necessary since we can't get rid of the generic keypair
            if (key.getType() != AsymmetricKey::KeyTypes::RSA) {
                throw MoCOCrWException("Expected RSA Key for RSA operation");
            }
        }

        Key key;
        std::shared_ptr<PaddingBase> padding;
    };


    /*
     * Intermediate base type for RSA Encryption Contexts
     */
    template<class Key>
    using RSAEncryptionImpl = RSAImpl<Key, RSAEncryptionPadding>;

    /*
     * PIMPL-Class of RSAEncryptionPrivateKeyCtx
     */
    class RSAEncryptionPrivateKeyCtx::Impl : public RSAEncryptionImpl<AsymmetricPrivateKey> {
        using RSAEncryptionImpl<AsymmetricPrivateKey>::RSAEncryptionImpl;
    };

    RSAEncryptionPrivateKeyCtx::RSAEncryptionPrivateKeyCtx(const AsymmetricPrivateKey& key,
                                                           std::shared_ptr<RSAEncryptionPadding> padding)
        : _impl(std::make_unique<RSAEncryptionPrivateKeyCtx::Impl>(key, padding)) {}

    RSAEncryptionPrivateKeyCtx::~RSAEncryptionPrivateKeyCtx() = default;

    RSAEncryptionPrivateKeyCtx::RSAEncryptionPrivateKeyCtx(const RSAEncryptionPrivateKeyCtx& other)
        : _impl(std::make_unique<RSAEncryptionPrivateKeyCtx::Impl>(*(other._impl))) {}

    RSAEncryptionPrivateKeyCtx& RSAEncryptionPrivateKeyCtx::operator=(const RSAEncryptionPrivateKeyCtx& other) {
        this->_impl = std::make_unique<RSAEncryptionPrivateKeyCtx::Impl>(*(other._impl));
        return *this;
    }

    std::vector<uint8_t> RSAEncryptionPrivateKeyCtx::decrypt(const std::vector<uint8_t>& message) {
        size_t decryptedMessageLen{0};
        SSL_RSA_ENCRYPTION_DATA_Ptr decryptedMessage{nullptr};

        try {
            auto keyCtx = _EVP_PKEY_CTX_new(_impl->key.internal());
            _EVP_PKEY_decrypt_init(keyCtx.get());

            /* Preform padding specific configurations*/
            _impl->padding->prepareOpenSSLContext(keyCtx);

            /* First call to determine the buffer length */
            _EVP_PKEY_decrypt(keyCtx.get(), nullptr, &decryptedMessageLen,
                              reinterpret_cast<const unsigned char *>(message.data()),
                              message.size());

            decryptedMessage.reset(static_cast<unsigned char*>(
                                           _OPENSSL_malloc(static_cast<int>(decryptedMessageLen))));

            /* Second call to perform the actual decryption */
            _EVP_PKEY_decrypt(keyCtx.get(), decryptedMessage.get(), &decryptedMessageLen,
                              reinterpret_cast<const unsigned char *>(message.data()),
                              message.size());

        } catch (const OpenSSLException &e) {
            throw MoCOCrWException(e.what());
        }

        return std::vector<uint8_t>(decryptedMessage.get(),
                                    decryptedMessage.get() + decryptedMessageLen);
    }

    /*
     * PIMPL-Class of RSAEncryptionPublicKeyCtx
     */
    class RSAEncryptionPublicKeyCtx::Impl : public RSAEncryptionImpl<AsymmetricPublicKey> {
        using RSAEncryptionImpl<AsymmetricPublicKey>::RSAEncryptionImpl;
    };

    RSAEncryptionPublicKeyCtx::RSAEncryptionPublicKeyCtx(const AsymmetricPublicKey& key,
                                                         std::shared_ptr<RSAEncryptionPadding> padding)
        : _impl(std::make_unique<RSAEncryptionPublicKeyCtx::Impl>(key, padding)) {}

    RSAEncryptionPublicKeyCtx::RSAEncryptionPublicKeyCtx(const X509Certificate& cert,
                                                         std::shared_ptr<RSAEncryptionPadding> padding)
        : RSAEncryptionPublicKeyCtx(cert.getPublicKey(), padding) {}

    RSAEncryptionPublicKeyCtx::RSAEncryptionPublicKeyCtx(const RSAEncryptionPublicKeyCtx& other)
        : _impl(std::make_unique<RSAEncryptionPublicKeyCtx::Impl>(*(other._impl))) {}

    RSAEncryptionPublicKeyCtx::~RSAEncryptionPublicKeyCtx() = default;

    RSAEncryptionPublicKeyCtx& RSAEncryptionPublicKeyCtx::operator=(const RSAEncryptionPublicKeyCtx& other) {
        this->_impl = std::make_unique<RSAEncryptionPublicKeyCtx::Impl>(*(other._impl));
        return *this;
    }

    std::vector<uint8_t> RSAEncryptionPublicKeyCtx::encrypt(const std::vector<uint8_t>& message) {
        SSL_RSA_ENCRYPTION_DATA_Ptr encryptedMessage{nullptr};
        size_t encryptedMessageLen{0};

        try {
            auto keyCtx = _EVP_PKEY_CTX_new(_impl->key.internal());
            if (!keyCtx.get()) {
                throw MoCOCrWException("Encryption context is empty");
            }

            // Check if message can be encrypted using the given key
            if (static_cast<size_t>(std::numeric_limits<int>::max()) < message.size()) {
                throw MoCOCrWException("Message size exceeds possible key size");
            } else if (!_impl->padding->checkMessageSize(_impl->key, message.size())) {
                throw MoCOCrWException((boost::format{"Message of size %1% can't be encrypted using"
                                                      " the given key and padding"}
                                                      % message.size()).str());
            }

            _EVP_PKEY_encrypt_init(keyCtx.get());
            _impl->padding->prepareOpenSSLContext(keyCtx);

            /* First call to determine the buffer length */
            _EVP_PKEY_encrypt(keyCtx.get(),
                              nullptr,
                              &encryptedMessageLen,
                              reinterpret_cast<const unsigned char *>(message.data()),
                              message.size());

            /* Allocate memory for the buffer, based on the size returned by _EVP_PKEY_encrypt */
            encryptedMessage.reset(static_cast<unsigned char*>(
                                           _OPENSSL_malloc(static_cast<int>(encryptedMessageLen))));

            /* Second call to perform the actual encryption */
            _EVP_PKEY_encrypt(keyCtx.get(),
                              encryptedMessage.get(),
                              &encryptedMessageLen,
                              reinterpret_cast<const unsigned char *>(message.data()),
                              message.size());

        } catch (const OpenSSLException &e) {
            throw MoCOCrWException(e.what());
        }

        return std::vector<uint8_t>(encryptedMessage.get(),
                                    encryptedMessage.get() + encryptedMessageLen);

    }

    /*
     * ###################
     * #  RSA Signature  #
     * ###################
     */

    /*
     * Intermediate base class for RSA Signature PIMPL classes
     *
     * Implements the retrieving of the hash function to be used of the stored padding object
     */
    template <class Key>
    class RSASignatureImpl : public RSAImpl<Key, RSASignaturePadding>, public SignatureCtxImpl {
    public:
        RSASignatureImpl(const Key& key, openssl::DigestTypes hashFunction, std::shared_ptr<RSASignaturePadding> padding)
            : RSAImpl<Key, RSASignaturePadding>(key, padding), SignatureCtxImpl(hashFunction) {}
    };

    /*
     * PIMPL-Class for RSASignaturePrivateKeyCtx
     */
    class RSASignaturePrivateKeyCtx::Impl : public RSASignatureImpl<AsymmetricPrivateKey> {
        using RSASignatureImpl<AsymmetricPrivateKey>::RSASignatureImpl;
    };

    RSASignaturePrivateKeyCtx::RSASignaturePrivateKeyCtx(const AsymmetricPrivateKey& key,
                                                         openssl::DigestTypes hashFunction,
                                                         std::shared_ptr<RSASignaturePadding> padding)
        : _impl(std::make_unique<RSASignaturePrivateKeyCtx::Impl>(key, hashFunction, padding)) {}

    RSASignaturePrivateKeyCtx::RSASignaturePrivateKeyCtx(const RSASignaturePrivateKeyCtx& other)
        : _impl(std::make_unique<RSASignaturePrivateKeyCtx::Impl>(*(other._impl))) {}

    RSASignaturePrivateKeyCtx& RSASignaturePrivateKeyCtx::operator=(const RSASignaturePrivateKeyCtx& other) {
        this->_impl = std::make_unique<RSASignaturePrivateKeyCtx::Impl>(*(other._impl));
        return *this;
    }

    RSASignaturePrivateKeyCtx::~RSASignaturePrivateKeyCtx() = default;

    std::vector<uint8_t> RSASignaturePrivateKeyCtx::signDigest(const std::vector<uint8_t> &messageDigest) {
        size_t expectedDigestSize = Hash::getDigestSize(_impl->hashFunction);
        if (messageDigest.size() != expectedDigestSize) {
            throw MoCOCrWException((boost::format{"Expected digest of size %1%"}
                                                  % expectedDigestSize).str());
        }

        try {
            auto keyCtx = _EVP_PKEY_CTX_new(_impl->key.internal());
            _EVP_PKEY_sign_init(keyCtx.get());

            _impl->padding->prepareOpenSSLContext(keyCtx, _impl->hashFunction);

            return signHelper(keyCtx, messageDigest);
        }
        catch (const OpenSSLException &e) {
            throw MoCOCrWException(e.what());
        }
    }

    std::vector<uint8_t> RSASignaturePrivateKeyCtx::signMessage(const std::vector<uint8_t> &message) {
        return signDigest(createHash(_impl->hashFunction, message));
    }

    /*
     * PIMPL-Class for RSASignaturePublicKeyCtx
     */
    class RSASignaturePublicKeyCtx::Impl : public RSASignatureImpl<AsymmetricPublicKey> {
        using RSASignatureImpl<AsymmetricPublicKey>::RSASignatureImpl;
    };


    RSASignaturePublicKeyCtx::RSASignaturePublicKeyCtx(const AsymmetricPublicKey& key,
                                                       openssl::DigestTypes hashFunction,
                                                       std::shared_ptr<RSASignaturePadding> padding)
        : _impl(std::make_unique<RSASignaturePublicKeyCtx::Impl>(key, hashFunction, padding)) {}

    RSASignaturePublicKeyCtx::RSASignaturePublicKeyCtx(const X509Certificate& cert,
                                                       openssl::DigestTypes hashFunction,
                                                       std::shared_ptr<RSASignaturePadding> padding)
        : RSASignaturePublicKeyCtx(cert.getPublicKey(), hashFunction, padding) {}

    RSASignaturePublicKeyCtx::RSASignaturePublicKeyCtx(const RSASignaturePublicKeyCtx& other)
        : _impl(std::make_unique<RSASignaturePublicKeyCtx::Impl>(*(other._impl))) {}

    RSASignaturePublicKeyCtx& RSASignaturePublicKeyCtx::operator=(const RSASignaturePublicKeyCtx& other) {
        this->_impl = std::make_unique<RSASignaturePublicKeyCtx::Impl>(*(other._impl));
        return *this;
    }

    RSASignaturePublicKeyCtx::~RSASignaturePublicKeyCtx() = default;

    void RSASignaturePublicKeyCtx::verifyDigest(const std::vector<uint8_t> &signature,
                                                const std::vector<uint8_t> &messageDigest) {

        size_t expectedDigestSize = Hash::getDigestSize(_impl->hashFunction);
        if (messageDigest.size() != expectedDigestSize) {
            throw MoCOCrWException((boost::format{"Expected digest of size %1%"}
                                                  % expectedDigestSize).str());
        }

        try {
            auto keyCtx = _EVP_PKEY_CTX_new(_impl->key.internal());
            _EVP_PKEY_verify_init(keyCtx.get());

            _impl->padding->prepareOpenSSLContext(keyCtx, _impl->hashFunction);

            _EVP_PKEY_verify(keyCtx.get(),
                             reinterpret_cast<const unsigned char *>(signature.data()),
                             signature.size(),
                             reinterpret_cast<const unsigned char *>(messageDigest.data()),
                             messageDigest.size());
        }
        catch (const OpenSSLException &e) {
            throw MoCOCrWException(e.what());
        }
    }

    void RSASignaturePublicKeyCtx::verifyMessage(const std::vector<uint8_t> &signature,
                                                 const std::vector<uint8_t> &message) {
        verifyDigest(signature, createHash(_impl->hashFunction, message));
    }


    /* ###########
     * #  ECDSA  #
     * ###########
     */

namespace {
    /**
     * This is required for backwards compatibility, since we had a typo in ECDSA for a while.
     */
    ECDSASignatureFormat SDAtoDSASignatureFormat (ECSDASignatureFormat sigFormat) {
        return static_cast<ECDSASignatureFormat>(static_cast<int>(sigFormat));
    }

    std::vector<uint8_t> _Asn1ECSignatureToIEEE1363EcSignature(const std::vector<uint8_t> &signature,
                                                               size_t keySizeBytes) {
        auto ecdsa = _d2i_ECDSA_SIG(signature);

        auto r = _ECDSA_SIG_get0_r(ecdsa.get());
        auto s = _ECDSA_SIG_get0_s(ecdsa.get());

        std::vector<uint8_t> ieee = _BN_bn2binpad(r, keySizeBytes);
        std::vector<uint8_t> s_vec =_BN_bn2binpad(s, keySizeBytes);
        ieee.insert(ieee.end(), s_vec.begin(), s_vec.end());

        return ieee;
    }
}

    /*
     * Common base class for all PIMPL classes of the ECDSA contexts
     *
     * Implements the check if the given key is a ECC key in the constructor.
     */
    template <class Key>
    class ECDSAImpl : public SignatureCtxImpl {
    public:
        ECDSAImpl(const Key& key, openssl::DigestTypes hashFunction, ECDSASignatureFormat sigFormat)
            : SignatureCtxImpl(hashFunction), key(key), _sigFormat(sigFormat) {
            // Not really nice but necessary since we can't get rid of the generic keypair
            if (key.getType() != AsymmetricKey::KeyTypes::ECC) {
                throw mococrw::MoCOCrWException("Expected ECC Key for ECC signatures");
            }
        }

        Key key;
    protected:
        ECDSASignatureFormat _sigFormat;
    };


    /*
     * PIMPL-Class for ECDSASignaturePrivateKeyCtx
     */
    class ECDSASignaturePrivateKeyCtx::Impl : public ECDSAImpl<AsymmetricPrivateKey> {
    public:
        using ECDSAImpl<AsymmetricPrivateKey>::ECDSAImpl;

        std::vector<uint8_t> signDigest(const std::vector<uint8_t> &messageDigest) {
            std::vector<uint8_t> signature = _signAsn1(messageDigest);
            if (_sigFormat == ECDSASignatureFormat::ASN1_SEQUENCE_OF_INTS) {
                return signature;
            } else if (_sigFormat == ECDSASignatureFormat::IEEE1363) {
                return _Asn1ECSignatureToIEEE1363EcSignature(signature, (key.getKeySize() + 7) / 8);
            } else {
                throw MoCOCrWException("ECDSA Signature type not recognized.");
            }
        }

    private:
        std::vector<uint8_t> _signAsn1(const std::vector<uint8_t> &messageDigest) {
            size_t expectedDigestSize = Hash::getDigestSize(hashFunction);
            if (messageDigest.size() != expectedDigestSize) {
                throw MoCOCrWException((boost::format{"Expected digest of size %1%"}
                                                      % expectedDigestSize).str());
            }

            try {
                auto keyCtx = _EVP_PKEY_CTX_new(key.internal());
                _EVP_PKEY_sign_init(keyCtx.get());

                return signHelper(keyCtx, messageDigest);
            }
            catch (const OpenSSLException &e) {
                throw MoCOCrWException(e.what());
            }
        }
    };

    ECDSASignaturePrivateKeyCtx::ECDSASignaturePrivateKeyCtx(const AsymmetricPrivateKey& key,
                                                             openssl::DigestTypes hashFunction)
        : _impl(std::make_unique<ECDSASignaturePrivateKeyCtx::Impl>(key, hashFunction, ECDSASignatureFormat::ASN1_SEQUENCE_OF_INTS)) {}

    ECDSASignaturePrivateKeyCtx::ECDSASignaturePrivateKeyCtx(const AsymmetricPrivateKey& key,
                                                             openssl::DigestTypes hashFunction,
                                                             ECDSASignatureFormat sigFormat)
        : _impl(std::make_unique<ECDSASignaturePrivateKeyCtx::Impl>(key, hashFunction, sigFormat)) {}

    ECDSASignaturePrivateKeyCtx::ECDSASignaturePrivateKeyCtx(const ECDSASignaturePrivateKeyCtx& other)
        : _impl(std::make_unique<ECDSASignaturePrivateKeyCtx::Impl>(*(other._impl))) {}

    ECDSASignaturePrivateKeyCtx& ECDSASignaturePrivateKeyCtx::operator=(const ECDSASignaturePrivateKeyCtx& other) {
        this->_impl = std::make_unique<ECDSASignaturePrivateKeyCtx::Impl>(*(other._impl));
        return *this;
    }

    ECDSASignaturePrivateKeyCtx::~ECDSASignaturePrivateKeyCtx() = default;

    std::vector<uint8_t> ECDSASignaturePrivateKeyCtx::signDigest(const std::vector<uint8_t> &messageDigest) {
        return _impl->signDigest(messageDigest);
    }

    std::vector<uint8_t> ECDSASignaturePrivateKeyCtx::signMessage(const std::vector<uint8_t> &message) {
        return signDigest(createHash(_impl->hashFunction, message));
    }

namespace {
    std::vector<uint8_t> _IEEE1363EcSignatureToAsn1ECSignature(const std::vector<uint8_t> &signature,
                                                               size_t keySizeBytes) {
        if (signature.size() != 2*keySizeBytes) {
            throw MoCOCrWException("Invalid signature size.");
        }
        auto r = _BN_bin2bn(signature.data(), keySizeBytes);
        auto s = _BN_bin2bn(signature.data() + keySizeBytes, keySizeBytes);
        if (r == nullptr || s == nullptr) {
            throw MoCOCrWException("Cannot extract ECDSA signature components");
        }
        auto ecdsa = createManagedOpenSSLObject<SSL_ECDSA_SIG_Ptr>();
        _ECDSA_SIG_set0(ecdsa.get(), std::move(r), std::move(s));
        return _i2d_ECDSA_SIG(ecdsa.get());
    }
}

    /*
     * PIMPL-Class for ECDSASignaturePublicKeyCtx
     */
    class ECDSASignaturePublicKeyCtx::Impl : public ECDSAImpl<AsymmetricPublicKey> {
    public:
        using ECDSAImpl<AsymmetricPublicKey>::ECDSAImpl;

        void verifyDigest(const std::vector<uint8_t> &signature,
                          const std::vector<uint8_t> &messageDigest) {
            if (_sigFormat == ECDSASignatureFormat::IEEE1363) {
                size_t keySizeBytes = (key.getKeySize() + 7) / 8;
                auto asn1Signature = _IEEE1363EcSignatureToAsn1ECSignature(signature, keySizeBytes);
                _verifyAsn1(asn1Signature, messageDigest);
            } else if (_sigFormat == ECDSASignatureFormat::ASN1_SEQUENCE_OF_INTS) {
                _verifyAsn1(signature, messageDigest);
            } else {
                throw MoCOCrWException("ECDSA Signature type not recognized.");
            }
        }

        void verifyMessage(const std::vector<uint8_t> &signature,
                           const std::vector<uint8_t> &message) {
            verifyDigest(signature, createHash(hashFunction, message));
        }

    private:
        void _verifyAsn1(const std::vector<uint8_t> &signature,
                         const std::vector<uint8_t> &messageDigest) {

            size_t expectedDigestSize = Hash::getDigestSize(hashFunction);
            if (messageDigest.size() != expectedDigestSize) {
                throw MoCOCrWException((boost::format{"Expected digest of size %1%"}
                                                    % expectedDigestSize).str());
            }

            try {
                auto keyCtx = _EVP_PKEY_CTX_new(key.internal());
                _EVP_PKEY_verify_init(keyCtx.get());

                _EVP_PKEY_verify(keyCtx.get(),
                                 reinterpret_cast<const unsigned char *>(signature.data()),
                                 signature.size(),
                                 reinterpret_cast<const unsigned char *>(messageDigest.data()),
                                 messageDigest.size());
            }
            catch (const OpenSSLException &e) {
                throw MoCOCrWException(e.what());
            }
        }
    };

    ECDSASignaturePublicKeyCtx::ECDSASignaturePublicKeyCtx(const AsymmetricPublicKey& key,
                                                           openssl::DigestTypes hashFunction,
                                                           ECSDASignatureFormat format)
        : _impl(std::make_unique<ECDSASignaturePublicKeyCtx::Impl>(key, hashFunction, SDAtoDSASignatureFormat(format))) {}

    ECDSASignaturePublicKeyCtx::ECDSASignaturePublicKeyCtx(const AsymmetricPublicKey& key,
                                                           openssl::DigestTypes hashFunction,
                                                           ECDSASignatureFormat format)
        : _impl(std::make_unique<ECDSASignaturePublicKeyCtx::Impl>(key, hashFunction, format)) {}

    ECDSASignaturePublicKeyCtx::ECDSASignaturePublicKeyCtx(const AsymmetricPublicKey& key,
                                                           openssl::DigestTypes hashFunction)
        : ECDSASignaturePublicKeyCtx(key, hashFunction, ECDSASignatureFormat::ASN1_SEQUENCE_OF_INTS) {}

    ECDSASignaturePublicKeyCtx::ECDSASignaturePublicKeyCtx(const X509Certificate& cert,
                                                           openssl::DigestTypes hashFunction)
        : ECDSASignaturePublicKeyCtx(cert.getPublicKey(), hashFunction) {}

    ECDSASignaturePublicKeyCtx::ECDSASignaturePublicKeyCtx(const X509Certificate& cert,
                                                           openssl::DigestTypes hashFunction,
                                                           ECSDASignatureFormat format)
        : ECDSASignaturePublicKeyCtx(cert.getPublicKey(), hashFunction, SDAtoDSASignatureFormat(format)) {}

    ECDSASignaturePublicKeyCtx::ECDSASignaturePublicKeyCtx(const X509Certificate& cert,
                                                           openssl::DigestTypes hashFunction,
                                                           ECDSASignatureFormat format)
        : ECDSASignaturePublicKeyCtx(cert.getPublicKey(), hashFunction, format) {}

    ECDSASignaturePublicKeyCtx::ECDSASignaturePublicKeyCtx(const ECDSASignaturePublicKeyCtx& other)
        : _impl(std::make_unique<ECDSASignaturePublicKeyCtx::Impl>(*(other._impl))) {}

    ECDSASignaturePublicKeyCtx& ECDSASignaturePublicKeyCtx::operator=(const ECDSASignaturePublicKeyCtx& other) {
        this->_impl = std::make_unique<ECDSASignaturePublicKeyCtx::Impl>(*(other._impl));
        return *this;
    }

    ECDSASignaturePublicKeyCtx::~ECDSASignaturePublicKeyCtx() = default;


    void ECDSASignaturePublicKeyCtx::verifyDigest(const std::vector<uint8_t> &signature,
                                                  const std::vector<uint8_t> &messageDigest) {
        _impl->verifyDigest(signature, messageDigest);
    }


    void ECDSASignaturePublicKeyCtx::verifyMessage(const std::vector<uint8_t> &signature,
                                                   const std::vector<uint8_t> &message) {
        _impl->verifyMessage(signature, message);
    }

    /* ###########
     * #  EdDSA  #
     * ###########
     */

    /*
     * Common base class for all PIMPL classes of the EdDSA contexts
     *
     * Implements the check if the given key is an Ed448 or an Ed25519 key in the constructor.
     */
    template <class Key>
    class EdDSAImpl {
    public:
        EdDSAImpl(const Key& key) : key(key) {
            // Not really nice but necessary since we can't get rid of the generic keypair
            if (key.getType() != AsymmetricKey::KeyTypes::ECC_ED) {
                throw mococrw::MoCOCrWException("Expected Ed448 or Ed25519 Key for EdDSA signatures");
            }
        }

        Key key;
    };

    /*
     * PIMPL-Class for EdDSASignaturePrivateKeyCtx
     */
    class EdDSASignaturePrivateKeyCtx::Impl : public EdDSAImpl<AsymmetricPrivateKey> {
        using EdDSAImpl<AsymmetricPrivateKey>::EdDSAImpl;
    };

    EdDSASignaturePrivateKeyCtx::EdDSASignaturePrivateKeyCtx(const AsymmetricPrivateKey &key)
        : _impl(std::make_unique<EdDSASignaturePrivateKeyCtx::Impl>(key)) {}

    EdDSASignaturePrivateKeyCtx::~EdDSASignaturePrivateKeyCtx() = default;

    EdDSASignaturePrivateKeyCtx::EdDSASignaturePrivateKeyCtx(const EdDSASignaturePrivateKeyCtx &other)
        : _impl(std::make_unique<EdDSASignaturePrivateKeyCtx::Impl>(*(other._impl))) {}

    EdDSASignaturePrivateKeyCtx& EdDSASignaturePrivateKeyCtx::operator=(const EdDSASignaturePrivateKeyCtx &other) {
        _impl = std::make_unique<EdDSASignaturePrivateKeyCtx::Impl>(*(other._impl));
        return *this;
    }

    std::vector<uint8_t> EdDSASignaturePrivateKeyCtx::signMessage(const std::vector<uint8_t> &message) {
        std::vector<uint8_t> signature;
        try {
            auto mctx = _EVP_MD_CTX_create();
            _EVP_DigestSignInit(mctx.get(), DigestTypes::NONE, const_cast<EVP_PKEY*>(_impl->key.internal()));

            // This determines the buffer length
            size_t siglen = 0;
            _EVP_DigestSign(mctx.get(), nullptr, &siglen, message.data(), message.size());

            signature.resize(siglen);
            _EVP_DigestSign(mctx.get(), signature.data(), &siglen, message.data(), message.size());
        }
        catch (const OpenSSLException &e) {
            throw MoCOCrWException(e.what());
        }

        return signature;
    }

    /*
     * PIMPL-Class for EdDSASignaturePublicKeyCtx
     */
    class EdDSASignaturePublicKeyCtx::Impl : public EdDSAImpl<AsymmetricPublicKey> {
        using EdDSAImpl<AsymmetricPublicKey>::EdDSAImpl;
    };

    EdDSASignaturePublicKeyCtx::EdDSASignaturePublicKeyCtx(const AsymmetricPublicKey &key)
        : _impl(std::make_unique<EdDSASignaturePublicKeyCtx::Impl>(key)) {}

    EdDSASignaturePublicKeyCtx::EdDSASignaturePublicKeyCtx(const X509Certificate &cert)
        : EdDSASignaturePublicKeyCtx(cert.getPublicKey()) {}

    EdDSASignaturePublicKeyCtx::~EdDSASignaturePublicKeyCtx() = default;

    EdDSASignaturePublicKeyCtx::EdDSASignaturePublicKeyCtx(const EdDSASignaturePublicKeyCtx &other)
        :_impl(std::make_unique<EdDSASignaturePublicKeyCtx::Impl>(*(other._impl))) {}

    EdDSASignaturePublicKeyCtx& EdDSASignaturePublicKeyCtx::operator=(const EdDSASignaturePublicKeyCtx &other) {
        _impl = std::make_unique<EdDSASignaturePublicKeyCtx::Impl>(*(other._impl));
        return *this;
    }

    void EdDSASignaturePublicKeyCtx::verifyMessage(const std::vector<uint8_t> &signature,
                                                   const std::vector<uint8_t> &message) {
        try {
            auto mctx = _EVP_MD_CTX_create();
            _EVP_DigestVerifyInit(mctx.get(), openssl::DigestTypes::NONE, _impl->key.internal());
            _EVP_DigestVerify(mctx.get(), signature.data(), signature.size(), message.data(), message.size());
        }
        catch (const OpenSSLException &e) {
            throw MoCOCrWException(e.what());
        }
    }

}
