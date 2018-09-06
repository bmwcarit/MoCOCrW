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
#include <sstream>

#include <boost/format.hpp>

#include "mococrw/bio.h"
#include "mococrw/key.h"
#include "mococrw/error.h"

#include "mococrw/openssl_wrap.h"

namespace mococrw
{
using namespace openssl;
AsymmetricKeypair AsymmetricKeypair::generate()
{
    RSASpec defaultSpec{};
    return generate(defaultSpec);
}

AsymmetricKeypair AsymmetricKeypair::generateRSA()
{
    RSASpec defaultSpec{};
    return generate(defaultSpec);
}

AsymmetricKeypair AsymmetricKeypair::generateECC()
{
    ECCSpec defaultSpec{};
    return generate(defaultSpec);
}

AsymmetricKeypair AsymmetricKeypair::generate(const AsymmetricKey::Spec &keySpec)
{
    return AsymmetricKeypair{keySpec.generate()};
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

AsymmetricKey ECCSpec::generate() const {
   SSL_EVP_PKEY_Ptr pkey{nullptr};
   try {
        /*Setting the correct curve to generate the ECC key*/
        auto paramCtx = _EVP_PKEY_CTX_new_id(EVP_PKEY_EC);
        _EVP_PKEY_paramgen_init(paramCtx.get());
        _EVP_PKEY_CTX_set_ec_paramgen_curve_nid(paramCtx.get(),
               static_cast<int>(_curveNid));
        /*Set the curve ans1 flag so that we can save the key to a PEM format and reuse it later*/
        _EVP_PKEY_CTX_set_ec_param_enc(paramCtx.get(), OPENSSL_EC_NAMED_CURVE);
        auto params = _EVP_PKEY_paramgen(paramCtx.get());

        /*Key Generation*/
        auto keyCtx = _EVP_PKEY_CTX_new(params.get());
        _EVP_PKEY_keygen_init(keyCtx.get());
        pkey = _EVP_PKEY_keygen(keyCtx.get());

   } catch (const OpenSSLException &e) {
        throw MoCOCrWException(e.what());
   }
   return AsymmetricKey{std::move(pkey)};
}

std::unique_ptr<AsymmetricKey::Spec> AsymmetricKey::getKeySpec() const
{
    if(getType() == KeyTypes::ECC) {
        openssl::ellipticCurveNid keyNid;
        try {
            const EC_GROUP *group = _EC_KEY_get0_group(_EVP_PKEY_get0_EC_KEY(_key.get()));
            keyNid = static_cast<openssl::ellipticCurveNid>(_EC_GROUP_get_curve_name(group));
        } catch (const OpenSSLException &e) {
            throw MoCOCrWException(e.what());
        }
        return std::make_unique<ECCSpec>(keyNid);//ECCSpec{keyNid});
    } else if (getType() == KeyTypes::RSA){
        unsigned int nBits = getKeySize();
        return std::make_unique<RSASpec>(nBits);
    } else{
        throw MoCOCrWException("Key type not supported.");
    }
}
}
