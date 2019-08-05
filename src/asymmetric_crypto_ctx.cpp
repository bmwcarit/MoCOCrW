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

#include <boost/format.hpp>
#include <boost/variant.hpp>
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
    template <class Key, typename... AllowedPaddingTypes>
    class RSAImpl {
    public:
        /*
         * Constructor that checks the type of the given key
         */
        template <class Padding>
        RSAImpl(const Key& key, Padding padding) : key(key), padding(padding) {
            // Not really nice but necessary since we can't get rid of the generic keypair
            if (key.getType() != AsymmetricKey::KeyTypes::RSA) {
                throw MoCOCrWException("Expected RSA Key for RSA operation");
            }
        }

        /*
         * Visitor implementation for calling prepareOpenSSLContext()
         */
        class PrepareCtxVisitor : public boost::static_visitor<> {
        public:
            PrepareCtxVisitor(SSL_EVP_PKEY_CTX_Ptr& ctx) : ctx(ctx) {}

            template<typename T>
            void operator()(T& t) const {
                t.prepareOpenSSLContext(ctx);
            }

            SSL_EVP_PKEY_CTX_Ptr& ctx;
        };

        /*
         * Call prepareOpenSSLContext on the stored padding object
         */
        void prepareOpenSSLContext(SSL_EVP_PKEY_CTX_Ptr& ctx) {
            boost::apply_visitor(PrepareCtxVisitor(ctx), this->padding);
        }

        Key key;
        boost::variant<AllowedPaddingTypes...> padding;
    };

    /*
     * Intermediate base type for RSA Encryption Contexts
     */
    template<class Key>
    using RSAEncryptionImpl = RSAImpl<Key, PKCSEncryptionPadding, OAEPPadding, NoPadding>;

    /*
     * PIMPL-Class of RSAEncryptionPrivateKeyCtx
     */
    class RSAEncryptionPrivateKeyCtx::Impl : public RSAEncryptionImpl<AsymmetricPrivateKey> {
        using RSAEncryptionImpl<AsymmetricPrivateKey>::RSAEncryptionImpl;
    };

    RSAEncryptionPrivateKeyCtx::RSAEncryptionPrivateKeyCtx(const AsymmetricPrivateKey& key,
                                                           PKCSEncryptionPadding padding)
        : _impl(std::make_unique<RSAEncryptionPrivateKeyCtx::Impl>(key, std::move(padding))) {}

    RSAEncryptionPrivateKeyCtx::RSAEncryptionPrivateKeyCtx(const AsymmetricPrivateKey& key,
                                                           OAEPPadding padding)
        : _impl(std::make_unique<RSAEncryptionPrivateKeyCtx::Impl>(key, std::move(padding))) {}

    RSAEncryptionPrivateKeyCtx::RSAEncryptionPrivateKeyCtx(const AsymmetricPrivateKey& key,
                                                           NoPadding padding)
        : _impl(std::make_unique<RSAEncryptionPrivateKeyCtx::Impl>(key, std::move(padding))) {}

    RSAEncryptionPrivateKeyCtx::~RSAEncryptionPrivateKeyCtx() = default;

    RSAEncryptionPrivateKeyCtx::RSAEncryptionPrivateKeyCtx(const RSAEncryptionPrivateKeyCtx& other)
        : _impl(std::make_unique<RSAEncryptionPrivateKeyCtx::Impl>(*(other._impl))) {}

    RSAEncryptionPrivateKeyCtx& RSAEncryptionPrivateKeyCtx::operator=(const RSAEncryptionPrivateKeyCtx& other) {
        _impl = std::make_unique<RSAEncryptionPrivateKeyCtx::Impl>(*(other._impl));
        return *this;
    }

    std::vector<uint8_t> RSAEncryptionPrivateKeyCtx::decrypt(const std::vector<uint8_t>& message) {
        size_t decryptedMessageLen{0};
        SSL_RSA_ENCRYPTION_DATA_Ptr decryptedMessage{nullptr};

        try {
            auto keyCtx = _EVP_PKEY_CTX_new(_impl->key.internal());
            _EVP_PKEY_decrypt_init(keyCtx.get());

            /* Preform padding specific configurations*/
            _impl->prepareOpenSSLContext(keyCtx);

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
    public:

        /*
         * Visitor implementation to check if the given message can be encrypted using
         * the specified parameters
         */
        class CheckDataBlockSizeVisitor {
        public:
            CheckDataBlockSizeVisitor(AsymmetricPublicKey& key, size_t messageSize)
                : key(key), messageSize(messageSize) {}

            template<typename T>
            void operator()(T& t) const {
                // Throw if message size is greater than the key size
                int dataBlockSize = t.getDataBlockSize(key);
                if (dataBlockSize < 0 || static_cast<size_t>(dataBlockSize) < messageSize) {
                    throw MoCOCrWException("Message too long for RSA key size");
                }
            }

            void operator()(NoPadding& np) const {
                // Without padding key size must equal message size
                if (static_cast<size_t>(np.getDataBlockSize(key)) != messageSize) {
                    throw MoCOCrWException((boost::format{"When using NoPadding message size "
                                                          "(%1% Byte) must equal the key size "
                                                          "(%2% Byte)"}
                                                          % messageSize
                                                          % (key.getKeySize()/8)).str());
                }
            }

            AsymmetricPublicKey key;
            size_t messageSize;
        };

        /*
         * Check if message can be encrypted using the specified padding parameters
         */
        void checkDataBlockSize(size_t messageSize) {
            if (static_cast<size_t>(std::numeric_limits<int>::max()) < messageSize) {
                throw("Message size exceeds possible key size");
            }
            boost::apply_visitor(CheckDataBlockSizeVisitor(this->key, messageSize), this->padding);
        }
    };

    RSAEncryptionPublicKeyCtx::RSAEncryptionPublicKeyCtx(const AsymmetricPublicKey& key,
                                                         PKCSEncryptionPadding padding)
        : _impl(std::make_unique<RSAEncryptionPublicKeyCtx::Impl>(key, std::move(padding))) {}

    RSAEncryptionPublicKeyCtx::RSAEncryptionPublicKeyCtx(const AsymmetricPublicKey& key,
                                                         OAEPPadding padding)
        : _impl(std::make_unique<RSAEncryptionPublicKeyCtx::Impl>(key, std::move(padding))) {}

    RSAEncryptionPublicKeyCtx::RSAEncryptionPublicKeyCtx(const AsymmetricPublicKey& key,
                                                         NoPadding padding)
        : _impl(std::make_unique<RSAEncryptionPublicKeyCtx::Impl>(key, std::move(padding))) {}

    RSAEncryptionPublicKeyCtx::RSAEncryptionPublicKeyCtx(const X509Certificate& cert,
                                                         PKCSEncryptionPadding padding)
        : RSAEncryptionPublicKeyCtx(cert.getPublicKey(), std::move(padding)) {}

    RSAEncryptionPublicKeyCtx::RSAEncryptionPublicKeyCtx(const X509Certificate& cert,
                                                         OAEPPadding padding)
        : RSAEncryptionPublicKeyCtx(cert.getPublicKey(), std::move(padding)) {}

    RSAEncryptionPublicKeyCtx::RSAEncryptionPublicKeyCtx(const X509Certificate& cert,
                                                         NoPadding padding)
        : RSAEncryptionPublicKeyCtx(cert.getPublicKey(), std::move(padding)) {}

    RSAEncryptionPublicKeyCtx::RSAEncryptionPublicKeyCtx(const RSAEncryptionPublicKeyCtx& other)
        : _impl(std::make_unique<RSAEncryptionPublicKeyCtx::Impl>(*(other._impl))) {}

    RSAEncryptionPublicKeyCtx::~RSAEncryptionPublicKeyCtx() = default;

    RSAEncryptionPublicKeyCtx& RSAEncryptionPublicKeyCtx::operator=(const RSAEncryptionPublicKeyCtx& other) {
        _impl = std::make_unique<RSAEncryptionPublicKeyCtx::Impl>(*(other._impl));
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

            _impl->checkDataBlockSize(message.size());

            _EVP_PKEY_encrypt_init(keyCtx.get());
            _impl->prepareOpenSSLContext(keyCtx);

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
    class RSASignatureImpl : public RSAImpl<Key, PKCSSignaturePadding, PSSPadding> {
        using RSAImpl<Key, PKCSSignaturePadding, PSSPadding>::RSAImpl;
    public:
        /*
         * Visitor that implements the retrieving of the hash function to be used
         */
        class GetHashFunctionVisitor : public boost::static_visitor<> {
        public:
            typedef openssl::DigestTypes result_type;

            template<typename T>
            openssl::DigestTypes operator()(const T& t) const {
                return t.getHashFunction();
            }
        };

        /*
         * Retrieves the hash function to be used
         */
        openssl::DigestTypes getHashFunction() {
            return boost::apply_visitor(GetHashFunctionVisitor{}, this->padding);
        }
    };

    /*
     * PIMPL-Class for RSASignaturePrivateKeyCtx
     */
    class RSASignaturePrivateKeyCtx::Impl : public RSASignatureImpl<AsymmetricPrivateKey> {
        using RSASignatureImpl<AsymmetricPrivateKey>::RSASignatureImpl;
    };

    RSASignaturePrivateKeyCtx::RSASignaturePrivateKeyCtx(const AsymmetricPrivateKey& key,
                                                         PKCSSignaturePadding padding)
        : _impl(std::make_unique<RSASignaturePrivateKeyCtx::Impl>(key, std::move(padding))) {}

    RSASignaturePrivateKeyCtx::RSASignaturePrivateKeyCtx(const AsymmetricPrivateKey& key,
                                                         PSSPadding padding)
        : _impl(std::make_unique<RSASignaturePrivateKeyCtx::Impl>(key, std::move(padding))) {}

    RSASignaturePrivateKeyCtx::RSASignaturePrivateKeyCtx(const RSASignaturePrivateKeyCtx& other)
        : _impl(std::make_unique<RSASignaturePrivateKeyCtx::Impl>(*(other._impl))) {}

    RSASignaturePrivateKeyCtx& RSASignaturePrivateKeyCtx::operator=(const RSASignaturePrivateKeyCtx& other) {
        _impl = std::make_unique<RSASignaturePrivateKeyCtx::Impl>(*(other._impl));
        return *this;
    }

    RSASignaturePrivateKeyCtx::~RSASignaturePrivateKeyCtx() = default;

    std::vector<uint8_t> RSASignaturePrivateKeyCtx::signMessage(const std::vector<uint8_t> &message) {
        return signDigest(createHash(_impl->getHashFunction(), message));
    }

    std::vector<uint8_t> RSASignaturePrivateKeyCtx::signDigest(const std::vector<uint8_t> &messageDigest) {
        size_t expectedDigestSize = Hash::getDigestSize(_impl->getHashFunction());
        if (messageDigest.size() != expectedDigestSize) {
            throw MoCOCrWException((boost::format{"Expected digest of size %1%"}
                                                  % expectedDigestSize).str());
        }

        try {
            auto keyCtx = _EVP_PKEY_CTX_new(_impl->key.internal());
            _EVP_PKEY_sign_init(keyCtx.get());

            _impl->prepareOpenSSLContext(keyCtx);

            return signHelper(keyCtx, messageDigest);
        }
        catch (const OpenSSLException &e) {
            throw MoCOCrWException(e.what());
        }
    }

    /*
     * PIMPL-Class for RSASignaturePublicKeyCtx
     */
    class RSASignaturePublicKeyCtx::Impl : public RSASignatureImpl<AsymmetricPublicKey> {
        using RSASignatureImpl<AsymmetricPublicKey>::RSASignatureImpl;
    };


    RSASignaturePublicKeyCtx::RSASignaturePublicKeyCtx(const AsymmetricPublicKey& key,
                                                       PKCSSignaturePadding padding)
        : _impl(std::make_unique<RSASignaturePublicKeyCtx::Impl>(key, std::move(padding))) {}

    RSASignaturePublicKeyCtx::RSASignaturePublicKeyCtx(const AsymmetricPublicKey& key,
                                                       PSSPadding padding)
        : _impl(std::make_unique<RSASignaturePublicKeyCtx::Impl>(key, std::move(padding))) {}

    RSASignaturePublicKeyCtx::RSASignaturePublicKeyCtx(const X509Certificate& cert,
                                                       PKCSSignaturePadding padding)
        : RSASignaturePublicKeyCtx(cert.getPublicKey(), std::move(padding)) {}

    RSASignaturePublicKeyCtx::RSASignaturePublicKeyCtx(const X509Certificate& cert,
                                                       PSSPadding padding)
        : RSASignaturePublicKeyCtx(cert.getPublicKey(), std::move(padding)) {}

    RSASignaturePublicKeyCtx::RSASignaturePublicKeyCtx(const RSASignaturePublicKeyCtx& other)
        : _impl(std::make_unique<RSASignaturePublicKeyCtx::Impl>(*(other._impl))) {}

    RSASignaturePublicKeyCtx& RSASignaturePublicKeyCtx::operator=(const RSASignaturePublicKeyCtx& other) {
        _impl = std::make_unique<RSASignaturePublicKeyCtx::Impl>(*(other._impl));
        return *this;
    }

    RSASignaturePublicKeyCtx::~RSASignaturePublicKeyCtx() = default;

    void RSASignaturePublicKeyCtx::verifyMessage(const std::vector<uint8_t> &signature,
                                                 const std::vector<uint8_t> &message) {
        verifyDigest(signature, createHash(_impl->getHashFunction(), message));
    }

    void RSASignaturePublicKeyCtx::verifyDigest(const std::vector<uint8_t> &signature,
                                                const std::vector<uint8_t> &messageDigest) {

        size_t expectedDigestSize = Hash::getDigestSize(_impl->getHashFunction());
        if (messageDigest.size() != expectedDigestSize) {
            throw MoCOCrWException((boost::format{"Expected digest of size %1%"}
                                                  % expectedDigestSize).str());
        }

        try {
            auto keyCtx = _EVP_PKEY_CTX_new(_impl->key.internal());
            _EVP_PKEY_verify_init(keyCtx.get());

            _impl->prepareOpenSSLContext(keyCtx);

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

    /* ###########
     * #  ECDSA  #
     * ###########
     */

    /*
     * Common base class for all PIMPL classes of the ECDSA contexts
     *
     * Implements the check if the given key is a ECC key in the constructor.
     */
    template <class Key>
    class ECDSAImpl {
    public:
        ECDSAImpl(const Key& key, openssl::DigestTypes hashFunction) : key(key), hashFunction(hashFunction) {
            // Not really nice but necessary since we can't get rid of the generic keypair
            if (key.getType() != AsymmetricKey::KeyTypes::ECC) {
                throw mococrw::MoCOCrWException("Expected ECC Key for ECC signatures");
            }
        }

        Key key;
        openssl::DigestTypes hashFunction;
    };


    /*
     * PIMPL-Class for ECDSASignaturePrivateKeyCtx
     */
    class ECDSASignaturePrivateKeyCtx::Impl : public ECDSAImpl<AsymmetricPrivateKey> {
        using ECDSAImpl<AsymmetricPrivateKey>::ECDSAImpl;
    };

    ECDSASignaturePrivateKeyCtx::ECDSASignaturePrivateKeyCtx(const AsymmetricPrivateKey& key,
                                                             openssl::DigestTypes hashFunction)
        : _impl(std::make_unique<ECDSASignaturePrivateKeyCtx::Impl>(key, hashFunction)) {}

    ECDSASignaturePrivateKeyCtx::ECDSASignaturePrivateKeyCtx(const ECDSASignaturePrivateKeyCtx& other)
        : _impl(std::make_unique<ECDSASignaturePrivateKeyCtx::Impl>(*(other._impl))) {}

    ECDSASignaturePrivateKeyCtx& ECDSASignaturePrivateKeyCtx::operator=(const ECDSASignaturePrivateKeyCtx& other) {
        _impl = std::make_unique<ECDSASignaturePrivateKeyCtx::Impl>(*(other._impl));
        return *this;
    }

    ECDSASignaturePrivateKeyCtx::~ECDSASignaturePrivateKeyCtx() = default;

    std::vector<uint8_t> ECDSASignaturePrivateKeyCtx::signMessage(const std::vector<uint8_t> &message) {
        return signDigest(createHash(_impl->hashFunction, message));
    }

    std::vector<uint8_t> ECDSASignaturePrivateKeyCtx::signDigest(const std::vector<uint8_t> &messageDigest) {
        size_t expectedDigestSize = Hash::getDigestSize(_impl->hashFunction);
        if (messageDigest.size() != expectedDigestSize) {
            throw MoCOCrWException((boost::format{"Expected digest of size %1%"}
                                                  % expectedDigestSize).str());
        }

        try {
            auto keyCtx = _EVP_PKEY_CTX_new(_impl->key.internal());
            _EVP_PKEY_sign_init(keyCtx.get());

            return signHelper(keyCtx, messageDigest);
        }
        catch (const OpenSSLException &e) {
            throw MoCOCrWException(e.what());
        }
    }

    /*
     * PIMPL-Class for ECDSASignaturePublicKeyCtx
     */
    class ECDSASignaturePublicKeyCtx::Impl : public ECDSAImpl<AsymmetricPublicKey> {
        using ECDSAImpl<AsymmetricPublicKey>::ECDSAImpl;
    };

    ECDSASignaturePublicKeyCtx::ECDSASignaturePublicKeyCtx(const AsymmetricPublicKey& key,
                                                           openssl::DigestTypes hashFunction)
        : _impl(std::make_unique<ECDSASignaturePublicKeyCtx::Impl>(key, hashFunction)) {}

    ECDSASignaturePublicKeyCtx::ECDSASignaturePublicKeyCtx(const X509Certificate& cert,
                                                           openssl::DigestTypes hashFunction)
        : ECDSASignaturePublicKeyCtx(cert.getPublicKey(), hashFunction) {}

    ECDSASignaturePublicKeyCtx::ECDSASignaturePublicKeyCtx(const ECDSASignaturePublicKeyCtx& other)
        : _impl(std::make_unique<ECDSASignaturePublicKeyCtx::Impl>(*(other._impl))) {}

    ECDSASignaturePublicKeyCtx& ECDSASignaturePublicKeyCtx::operator=(const ECDSASignaturePublicKeyCtx& other) {
        _impl = std::make_unique<ECDSASignaturePublicKeyCtx::Impl>(*(other._impl));
        return *this;
    }

    ECDSASignaturePublicKeyCtx::~ECDSASignaturePublicKeyCtx() = default;


    void ECDSASignaturePublicKeyCtx::verifyMessage(const std::vector<uint8_t> &signature,
                                                   const std::vector<uint8_t> &message) {
        verifyDigest(signature, createHash(_impl->hashFunction, message));
    }

    void ECDSASignaturePublicKeyCtx::verifyDigest(const std::vector<uint8_t> &signature,
                                                  const std::vector<uint8_t> &messageDigest) {

        size_t expectedDigestSize = Hash::getDigestSize(_impl->hashFunction);
        if (messageDigest.size() != expectedDigestSize) {
            throw MoCOCrWException((boost::format{"Expected digest of size %1%"}
                                                  % expectedDigestSize).str());
        }

        try {
            auto keyCtx = _EVP_PKEY_CTX_new(_impl->key.internal());
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
}
