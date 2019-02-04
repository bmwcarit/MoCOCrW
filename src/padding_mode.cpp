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

#include "mococrw/padding_mode.h"

namespace mococrw {

using namespace openssl;

using SSL_RSA_OAEP_LABEL_Ptr = std::unique_ptr<uint8_t, SSLFree<uint8_t>>;


bool  NoPadding::isOperationSupported(const OperationTypes& op) const
{
    if (op == OperationTypes::Encrypt || op == OperationTypes::Decrypt) {
        return true;
    }
    else {
        return false;
    }
}

void PKCSPadding::prepareOpenSSLContext(openssl::SSL_EVP_PKEY_CTX_Ptr& ctx, const OperationTypes &op)
{
    _EVP_PKEY_CTX_set_rsa_padding(ctx.get(), static_cast<int>(getPadding()));
    if(op == OperationTypes::Sign || op == OperationTypes::Verify){
        _EVP_PKEY_CTX_set_signature_md(ctx.get(), _getMDPtrFromDigestType(_hashingFunction));
    }
}

void PSSPadding::prepareOpenSSLContext(openssl::SSL_EVP_PKEY_CTX_Ptr& ctx, const OperationTypes &op)
{
    if(op == OperationTypes::Sign || op == OperationTypes::Verify){
        _EVP_PKEY_CTX_set_rsa_padding(ctx.get(), static_cast<int>(getPadding()));
        _EVP_PKEY_CTX_set_signature_md(ctx.get(), _getMDPtrFromDigestType(_hashingFunction));
        _EVP_PKEY_CTX_set_rsa_pss_saltlen(ctx.get(), _saltLength);
        _EVP_PKEY_CTX_set_rsa_mgf1_md(ctx.get(), _getMDPtrFromDigestType(_maskingFunction));
    }
}

bool PSSPadding::isOperationSupported(const OperationTypes& op) const
{
    if (op == OperationTypes::Sign || op == OperationTypes::Verify) {
        return true;
    }
    else {
        return false;
    }
}

void OAEPPadding::prepareOpenSSLContext(openssl::SSL_EVP_PKEY_CTX_Ptr& ctx, const OperationTypes &op)
{
    SSL_RSA_OAEP_LABEL_Ptr label_copy{nullptr};

    if (op == OperationTypes::Encrypt || op == OperationTypes::Decrypt) {
        try {
            _EVP_PKEY_CTX_set_rsa_padding(ctx.get(), static_cast<int>(getPadding()));

            _EVP_PKEY_CTX_set_rsa_oaep_md(ctx.get(),
                                          _getMDPtrFromDigestType(_hashingFunction));

            _EVP_PKEY_CTX_set_rsa_mgf1_md(ctx.get(),
                                          _getMDPtrFromDigestType(_maskingFunction));

            if (!_label.empty()) {

                /* Make a copy of the label, since the context takes ownership of it when calling
                 * '_EVP_PKEY_CTX_set_rsa_oaep_label()' function */
                label_copy.reset(static_cast<uint8_t *>(
                                         _OPENSSL_malloc(_label.size())));
                memcpy(label_copy.get(),
                       &_label[0], _label.size());

                _EVP_PKEY_CTX_set_rsa_oaep_label(ctx.get(),
                                                 static_cast<unsigned char *>(label_copy.get()),
                                                 static_cast<int>(_label.size()));

                /* Release ownership from the unique_ptr since the function above takes ownership of
                 * the label pointer unless it throws an exception*/
                std::ignore = label_copy.release();
            }
        } catch (const OpenSSLException &e) {
            throw MoCOCrWException(e.what());
        }
    }
}

bool  OAEPPadding::isOperationSupported(const OperationTypes& op) const
{
    if (op == OperationTypes::Encrypt || op == OperationTypes::Decrypt) {
        return true;
    }
    else {
        return false;
    }
}

}

