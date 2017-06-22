/**
 * @file
 * @copyright (C) 2017, BMW AG
 * @copyright (C) 2017, BMW Car IT GmbH
 */

#include <sstream>

#include <boost/format.hpp>

#include "mococrw/bio.h"
#include "mococrw/key.h"

#include "mococrw/openssl_wrap.h"

namespace mococrw
{
using namespace openssl;
AsymmetricKeypair AsymmetricKeypair::generate()
{
    RSASpec defaultSpec{};
    return AsymmetricKeypair{defaultSpec.generate()};
}

std::string AsymmetricPublicKey::publicKeyToPem() const
{
    BioObject bio{BioObject::Types::MEM};
    _PEM_write_bio_PUBKEY(bio.internal(), _key.internal().get());
    return bio.flushToString();
}

AsymmetricPublicKey AsymmetricPublicKey::readPublicKeyFromPEM(const std::string& pem)
{
    BioObject bio{BioObject::Types::MEM};
    bio.write(pem);
    auto key = _PEM_read_bio_PUBKEY(bio.internal());
    return AsymmetricPublicKey{std::move(key)};
}

std::string AsymmetricKeypair::privateKeyToPem(const std::string& pwd) const
{
    BioObject bio{BioObject::Types::MEM};
    const EVP_CIPHER *pkey_cipher = nullptr;
    if (pwd.size() > 0) {
        // only set a cipher if we do want to set a password
        pkey_cipher = _EVP_aes_256_cbc();
    }
    _PEM_write_bio_PKCS8PrivateKey(bio.internal(),
                                   _key.internal().get(),
                                   pkey_cipher,
                                   pwd);
    return bio.flushToString();
}

// In OpenSSL, private keys are the same as keypairs, in that they also contain the public key.
AsymmetricKeypair AsymmetricKeypair::readPrivateKeyFromPEM(const std::string& pem,
                                                    const std::string& password)
{
    BioObject bio{BioObject::Types::MEM};
    bio.write(pem);
    auto key = _PEM_read_bio_PrivateKey(bio.internal(), password.c_str());
    return AsymmetricKeypair{std::move(key)};
}

AsymmetricKey RSASpec::generate() const
{
    auto keyCtx = _EVP_PKEY_CTX_new_id(EVP_PKEY_RSA);
    _EVP_PKEY_keygen_init(keyCtx.get());

    _EVP_PKEY_CTX_set_rsa_keygen_bits(keyCtx.get(), _numBits);

    auto pkey = _EVP_PKEY_keygen(keyCtx.get());
    return AsymmetricKey{std::move(pkey)};
}
}
